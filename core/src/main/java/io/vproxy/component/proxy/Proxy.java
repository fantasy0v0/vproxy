package io.vproxy.component.proxy;

import io.vproxy.base.connection.*;
import io.vproxy.base.processor.ConnectionDelegate;
import io.vproxy.base.processor.Processor;
import io.vproxy.base.protocol.ProtocolConnectionHandler;
import io.vproxy.base.protocol.ProtocolHandler;
import io.vproxy.base.protocol.ProtocolHandlerContext;
import io.vproxy.base.util.LogType;
import io.vproxy.base.util.Logger;
import io.vproxy.base.util.RingBuffer;
import io.vproxy.base.util.Utils;
import io.vproxy.base.util.callback.Callback;
import io.vproxy.base.util.coll.ConcurrentHashSet;
import io.vproxy.base.util.coll.Tuple;
import io.vproxy.base.util.ringbuffer.ByteBufferRingBuffer;
import io.vproxy.base.util.ringbuffer.ProxyOutputRingBuffer;
import io.vproxy.base.util.ringbuffer.SSLUtils;
import io.vproxy.base.util.ringbuffer.ssl.SSL;
import io.vproxy.base.util.ringbuffer.ssl.SSLEngineBuilder;
import vproxy.base.connection.*;
import io.vproxy.base.processor.ConnectionDelegate;
import io.vproxy.base.processor.Processor;
import io.vproxy.base.protocol.ProtocolConnectionHandler;
import io.vproxy.base.protocol.ProtocolHandler;
import io.vproxy.base.protocol.ProtocolHandlerContext;
import io.vproxy.base.util.LogType;
import io.vproxy.base.util.Logger;
import io.vproxy.base.util.RingBuffer;
import io.vproxy.base.util.Utils;
import io.vproxy.base.util.callback.Callback;
import io.vproxy.base.util.coll.ConcurrentHashSet;
import vproxy.base.util.coll.Tuple;
import io.vproxy.base.util.ringbuffer.ByteBufferRingBuffer;
import io.vproxy.base.util.ringbuffer.ProxyOutputRingBuffer;
import io.vproxy.base.util.ringbuffer.SSLUtils;
import io.vproxy.base.util.ringbuffer.ssl.SSL;
import io.vproxy.base.util.ringbuffer.ssl.SSLEngineBuilder;
import io.vproxy.vfd.SocketFD;

import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.util.Collection;

/**
 * when a connection is accepted, another connection will be generated by calling the callback handler<br>
 * the accepted connection and the new connection form up a {@link Session}<br>
 * the session operations will always be handled in the same event loop
 */
public class Proxy {
    private static void utilCloseConnection(Connection connection) {
        assert Logger.lowLevelDebug("close connection " + connection);
        connection.closeKeepBuffers();
    }

    private static void utilCloseConnectionAndReleaseBuffers(Connection connection) {
        utilCloseConnection(connection);
        connection.getInBuffer().clean();
        connection.getOutBuffer().clean();
    }

    private static void utilCloseSessionAndReleaseBuffers(Session session) {
        utilCloseConnectionAndReleaseBuffers(session.active);
        utilCloseConnection(session.passive);
    }

    class SessionServerHandler implements ServerHandler {
        @Override
        public void acceptFail(ServerHandlerContext ctx, IOException err) {
            Logger.fatal(LogType.SERVER_ACCEPT_FAIL, "accept connection failed, server = " + config.server + ", err = " + err);
        }

        @Override
        public void connection(ServerHandlerContext ctx, Connection connection) {
            NetEventLoop acceptLoop = ctx.eventLoop;
            switch (config.connGen.type()) {
                case processor:
                    handleProcessor(acceptLoop, connection);
                    break;
                case handler:
                    handleHandler(acceptLoop, connection);
                    break;
                case direct:
                default:
                    handleDirect(acceptLoop, connection);
            }
        }

        private void handleDirect(NetEventLoop acceptLoop, Connection connection) {
            // make connection to another end point
            Connector connector = config.connGen.genConnector(connection, /*directly proxy does not require hint*/ null);
            handleDirect(acceptLoop, connection, connector);
        }

        private void handleDirect(NetEventLoop acceptLoop, Connection connection, Connector connector) {
            // check whether address tuple is null
            // null means the user code fail to provide a new connection
            // maybe user think that the backend is not working, or the source ip is forbidden
            // any way, the user refuse to provide a new connection
            if (connector == null) {
                Logger.info(LogType.NO_CLIENT_CONN, "the user code refuse to provide a remote endpoint");
                // close the active connection
                utilCloseConnectionAndReleaseBuffers(connection);
                return;
            }

            try {
                connector.beforeConnect(connection);
            } catch (IOException e) {
                Logger.fatal(LogType.CONN_ERROR, "running beforeConnect on connector failed", e);
                utilCloseConnectionAndReleaseBuffers(connection);
                connector.close();
                return;
            }

            ConnectableConnection connectableConnection;
            try {
                connectableConnection = connector.connect(
                    connection,
                    new ConnectionOpts().setTimeout(config.timeout),
                    /*switch the two buffers to make a PROXY*/connection.getOutBuffer(), connection.getInBuffer());
            } catch (IOException e) {
                Logger.fatal(LogType.CONN_ERROR, "make passive connection failed, maybe provided endpoint info is invalid", e);
                // it should not happen if user provided endpoint is valid
                // but if it happens, we close both sides

                utilCloseConnectionAndReleaseBuffers(connection);
                connector.close();
                return;
            }

            Session session = new Session(connection, connectableConnection);
            ConnectableConnectionHandler handler = new SessionConnectableConnectionHandler(session);

            // we get a new event loop for handling
            // the event loop is provided by user
            // user may use the same loop as the acceptLoop
            //
            // and we only register the passive connection here
            // the active connection will be registered
            // when the passive connection is successfully established
            NetEventLoop loop;
            {
                NetEventLoop foo = connector.loop();
                if (foo == null) {
                    assert Logger.lowLevelDebug("connector did not provide any loop, retrieve a new one");
                    loop = config.handleLoopProvider.getHandleLoop(acceptLoop);
                } else {
                    assert Logger.lowLevelDebug("connector provided a loop");
                    loop = foo;
                }
            }
            if (loop == null) {
                // the loop not exist
                utilCloseSessionAndReleaseBuffers(session);
                Logger.warn(LogType.NO_EVENT_LOOP, "cannot get event loop for connectable connection " + connectableConnection);
                return;
            }
            try {
                loop.addConnectableConnection(connectableConnection, null, handler);

                // here the handler added successfully, we can record the session
                sessions.add(session);
                // the session record will be removed in `removed()` callback

            } catch (IOException e) {
                Logger.fatal(LogType.EVENT_LOOP_ADD_FAIL, "register passive connection into event loop failed, passive conn = " + connectableConnection + ", err = " + e);
                // should not happen
                // but if it happens, we close both sides
                utilCloseSessionAndReleaseBuffers(session);
            }
        }

        class HandlerCallback extends Callback<Connector, IOException> {
            private final NetEventLoop acceptLoop;
            private final NetEventLoop loop;
            private final Connection active;

            HandlerCallback(NetEventLoop acceptLoop, NetEventLoop loop, Connection active) {
                this.acceptLoop = acceptLoop;
                this.loop = loop;
                this.active = active;
            }

            @Override
            protected void onSucceeded(Connector connector) {
                assert Logger.lowLevelDebug("HandlerCallback.onSucceeded called with connector: " + connector);
                // remove the connection from loop first
                // because we want to remove the old ConnectionHandler
                // then handle it as direct
                try {
                    loop.removeConnection(active);
                } catch (Throwable t) {
                    // will raise error if it's not in the loop
                    // which should not happen
                    // but if happens, we close the connection
                    Logger.shouldNotHappen("remove the active connection from loop failed", t);
                    return;
                }
                // we don't care whether the connector is null or not
                // will be checked in the following method

                // handle like a normal proxy:
                // next -> next tick to ensure that this connection is removed and adding it back will succeed
                loop.getSelectorEventLoop().doubleNextTick(() -> handleDirect(acceptLoop, active, connector));
            }

            @Override
            protected void onFailed(IOException err) {
                Logger.error(LogType.NO_CLIENT_CONN, "the user code got an exception", err);
                // we cannot handle the connection anymore
                // return an empty connector
                handleDirect(acceptLoop, active, null);
            }
        }

        @SuppressWarnings(/*ignore generics here*/"unchecked")
        private void handleHandler(NetEventLoop acceptLoop, Connection connection) {
            // retrieve the handler
            ProtocolHandler pHandler = config.connGen.handler();
            // retrieve an event loop provided by user code
            // the net flow will be handled here
            NetEventLoop loop = config.handleLoopProvider.getHandleLoop(acceptLoop);
            if (loop == null) {
                // the loop not exist
                Logger.warn(LogType.NO_EVENT_LOOP, "cannot get event loop for handler");
                connection.close(true);
                return;
            }

            // create a protocol context and init the handler
            ProtocolHandlerContext pctx = new ProtocolHandlerContext(connection.id(), connection, loop, pHandler);
            pHandler.init(pctx);

            // set callback
            Tuple<Object, Callback<Connector, IOException>> tup = (Tuple) pctx.data;
            if (tup == null) {
                // user code fail to provide the data
                Logger.error(LogType.IMPROPER_USE, "user code should set a tuple(T, null) to the data field");
                // close the connection because we cannot handle it anymore
                connection.close(true);
                return;
            }
            tup = new Tuple<>(tup.left, new HandlerCallback(acceptLoop, loop, connection));
            pctx.data = tup;

            // the following code should be same as in ProtocolServerHandler
            //noinspection Duplicates
            try {
                loop.addConnection(connection, pHandler, new ProtocolConnectionHandler(pctx));
            } catch (IOException e) {
                // handle exception in handler
                pHandler.exception(pctx, e);
                // and do some log
                Logger.error(LogType.EVENT_LOOP_ADD_FAIL, "add new connection into loop failed", e);
                // the connection should be closed by the lib
                connection.close(true);
            }
        }

        @SuppressWarnings("unchecked")
        private void handleProcessor(NetEventLoop acceptLoop, Connection frontendConnection) {
            // retrieve an event loop
            NetEventLoop loop = config.handleLoopProvider.getHandleLoop(acceptLoop);

            Processor processor = config.connGen.processor();
            Processor.Context topCtx = processor.init(frontendConnection.remote);
            ProcessorConnectionHandler[] handlerPtr = new ProcessorConnectionHandler[]{null};
            //noinspection DuplicatedCode
            Processor.SubContext frontendSubCtx = processor.initSub(topCtx, 0, new ConnectionDelegate(frontendConnection.remote) {
                @Override
                public void pause() {
                    assert handlerPtr[0] != null;
                    handlerPtr[0].pause();
                }

                @Override
                public void resume() {
                    assert handlerPtr[0] != null;
                    handlerPtr[0].resume();
                }
            });
            {
                Processor.HandleTODO todo = processor.connected(topCtx, frontendSubCtx);
                // currently we do not support sending nor producing when frontend connection is connected
                if (todo != null) {
                    if (todo.send != null) {
                        if (todo.send.length() > 0 || todo.send == Processor.REQUIRE_CONNECTION) {
                            Logger.warn(LogType.IMPROPER_USE, "currently we not support sending when frontend connection is connected");
                        }
                    }
                    if (todo.produce != null) {
                        if (todo.produce.length() > 0) {
                            Logger.warn(LogType.IMPROPER_USE, "currently we not support producing when frontend connection is connected");
                        }
                    }
                }
            }

            // initiate the handler
            handlerPtr[0] =
                new ProcessorConnectionHandler(
                    config,
                    loop,
                    frontendConnection,
                    processor,
                    topCtx,
                    frontendSubCtx
                );
            try {
                loop.addConnection(frontendConnection, null, handlerPtr[0]);
            } catch (IOException e) {
                // and do some log
                Logger.error(LogType.EVENT_LOOP_ADD_FAIL, "add new connection into loop failed", e);
                // the connection should be closed by the lib
                frontendConnection.close(true);
            }
        }

        @Override
        public Tuple<RingBuffer, RingBuffer> getIOBuffers(SocketFD channel) {
            int inBufferSize, outBufferSize;
            if (config.sslContext == null) {
                inBufferSize = config.inBufferSize;
                outBufferSize = config.outBufferSize;
            } else {
                // using ssl
                // make the buffer large enough to hold one packet
                inBufferSize = Math.max(config.inBufferSize, 24576);
                outBufferSize = Math.max(config.outBufferSize, 24576);
            }
            ByteBufferRingBuffer inBuffer = RingBuffer.allocateDirect(inBufferSize);
            RingBuffer outBuffer =
                (config.connGen.type() == ConnectorGen.Type.processor && config.sslContext == null)
                    ? ProxyOutputRingBuffer.allocateDirect(outBufferSize)
                    : RingBuffer.allocateDirect(outBufferSize);

            if (config.sslContext == null) {
                return new Tuple<>(inBuffer, outBuffer);
            }

            SSL ssl = config.sslContext.createSSL();
            SSLEngineBuilder builder = ssl.sslEngineBuilder;
            builder.configure(engine -> engine.setUseClientMode(false));
            builder.configure(engine -> engine.setNeedClientAuth(false));
            builder.configure(engine -> engine.setWantClientAuth(false));
            SSLParameters sslParams = new SSLParameters();
            {
                sslParams.setNeedClientAuth(false);
                sslParams.setWantClientAuth(false);
            }
            if (config.sslEngineManipulator != null) {
                builder.configure(engine -> config.sslEngineManipulator.accept(engine, sslParams));
            }
            builder.configure(engine -> engine.setSSLParameters(sslParams));
            // try to use alpn
            if (config.connGen.type() == ConnectorGen.Type.processor) {
                String[] alpn = config.connGen.processor().alpn();
                if (alpn != null) {
                    final var fAlpn = alpn.clone();
                    builder.configure(engine -> engine.setHandshakeApplicationProtocolSelector((e, ls) -> {
                        for (String s : fAlpn) {
                            if (ls.contains(s))
                                return s;
                        }
                        return null;
                    }));
                }
            }
            SSLUtils.SSLBufferPair pair = SSLUtils.genbufForServer(ssl, inBuffer, (ByteBufferRingBuffer) outBuffer, channel);
            return new Tuple<>(pair.left, pair.right);
        }

        @Override
        public void removed(ServerHandlerContext ctx) {
            handler.serverRemoved(ctx.server);
        }

        @Override
        public ConnectionOpts connectionOpts() {
            return new ConnectionOpts().setTimeout(config.timeout);
        }
    }

    static class SessionConnectionHandler implements ConnectionHandler {
        private final Session session;

        SessionConnectionHandler(Session session) {
            this.session = session;
        }

        @Override
        public void readable(ConnectionHandlerContext ctx) {
            // the input buffer is attached to remote write buffer
            // and output buffer is attached to remote read buffer
            // as a result,
            // the write and read process is automatically handled by the lib
        }

        @Override
        public void writable(ConnectionHandlerContext ctx) {
            // we might write the last bytes here
            // when we write everything, we close the connection
            if (session.passive.isClosed() && ctx.connection.getOutBuffer().used() == 0)
                utilCloseConnectionAndReleaseBuffers(ctx.connection);
        }

        @Override
        public void exception(ConnectionHandlerContext ctx, IOException err) {
            String side = (session.active == ctx.connection) ? "active" : "passive";
            if (Utils.isTerminatedIOException(err)) {
                assert Logger.lowLevelDebug("session " + session + " got exception on " + side + " side: " + err);
            } else {
                Logger.error(LogType.CONN_ERROR, "session " + session + " got exception on " + side + " side: " + err);
            }
            // close both sides
            utilCloseSessionAndReleaseBuffers(session);
        }

        @Override
        public void remoteClosed(ConnectionHandlerContext ctx) {
            assert Logger.lowLevelDebug("now the connection sent FIN, we should close output for the passive one");
            // now the active connection is closed
            if (session.isClosed()) // do nothing if the session is already closed
                return;
            // the frontend connection closed
            // we need to shutdownOutput for backend connection
            session.passive.closeWrite();

            // check whether need to close the session
            if (session.passive.getOutBuffer().used() == 0) {
                if (session.passive.isRemoteClosed()) {
                    // nothing to write anymore
                    // close the passive connection
                    assert Logger.lowLevelDebug("nothing to write for passive connection, do close");
                    utilCloseConnectionAndReleaseBuffers(session.passive);
                }
            }
        }

        @Override
        public void closed(ConnectionHandlerContext ctx) {
            assert Logger.lowLevelDebug("now the connection is closed, we should close the session");
            // now the active connection is closed
            if (session.isClosed()) // do nothing if the session is already closed
                return;
            if (session.passive.getOutBuffer().used() == 0) {
                // nothing to write anymore
                // close the passive connection
                assert Logger.lowLevelDebug("nothing to write for passive connection, do close");
                utilCloseConnectionAndReleaseBuffers(session.passive);
            }
        }

        @Override
        public void removed(ConnectionHandlerContext ctx) {
            utilCloseSessionAndReleaseBuffers(session);
        }
    }

    class SessionConnectableConnectionHandler implements ConnectableConnectionHandler {
        private final Session session;
        private boolean isConnected = false;

        SessionConnectableConnectionHandler(Session session) {
            this.session = session;
        }

        @Override
        public void connected(ConnectableConnectionHandlerContext ctx) {
            assert Logger.lowLevelDebug("passive connection established: " + session);
            isConnected = true; // it's connected

            // now we can add active connection into event loop
            // use event loop from context
            // the active and passive connection are handled in the same loop
            try {
                ctx.eventLoop.addConnection(session.active, null, new SessionConnectionHandler(session));
            } catch (IOException e) {
                Logger.fatal(LogType.EVENT_LOOP_ADD_FAIL, "register active connection into event loop failed, conn = " + session.active + ", err = " + e);
                // add into event loop failed
                // close session
                assert Logger.lowLevelDebug("nothing to write for active connection, do close");
                utilCloseSessionAndReleaseBuffers(session);
            }
        }

        @Override
        public void readable(ConnectionHandlerContext ctx) {
            // see readable in SessionConnectHandler#readable
        }

        @Override
        public void writable(ConnectionHandlerContext ctx) {
            // we might write the last bytes here
            // when we write everyhing, we close the connection
            if (session.active.isClosed() && ctx.connection.getOutBuffer().used() == 0)
                utilCloseConnectionAndReleaseBuffers(ctx.connection);
        }

        @Override
        public void exception(ConnectionHandlerContext ctx, IOException err) {
            String side = (session.active == ctx.connection) ? "active" : "passive";
            if (Utils.isTerminatedIOException(err)) {
                assert Logger.lowLevelDebug("session " + session + " got exception on " + side + " side: " + err);
            } else {
                Logger.error(LogType.CONN_ERROR, "session " + session + " got exception on " + side + " side: " + err);
            }
            // close both sides
            utilCloseSessionAndReleaseBuffers(session);

            if (!isConnected) {
                // the connection failed before established
                // we should alert the connector that the connection failed
                Connector connector = ((ConnectableConnection) ctx.connection).getConnector();
                if (connector != null) {
                    connector.connectionFailed();
                }
            }
        }

        @Override
        public void remoteClosed(ConnectionHandlerContext ctx) {
            assert Logger.lowLevelDebug("now the passive connection is closed, we should close output of the active one");
            // now the passive connection is closed
            if (session.isClosed()) // do nothing if the session is already closed
                return;
            // the connection to backend is closed
            // so we close the write direction of the frontend connection
            session.active.closeWrite();

            // check whether need to close the session
            if (session.active.getOutBuffer().used() == 0) {
                if (session.active.isRemoteClosed()) {
                    // nothing to write anymore
                    // close the active connection
                    utilCloseConnectionAndReleaseBuffers(session.active);
                }
            }
        }

        @Override
        public void closed(ConnectionHandlerContext ctx) {
            assert Logger.lowLevelDebug("now the passive connection is closed, we should close the session");
            // now the passive connection is closed
            if (session.isClosed()) // do nothing if the session is already closed
                return;
            if (session.active.getOutBuffer().used() == 0) {
                // nothing to write anymore
                // close the active connection
                utilCloseConnectionAndReleaseBuffers(session.active);
            }
        }

        @Override
        public void removed(ConnectionHandlerContext ctx) {
            utilCloseSessionAndReleaseBuffers(session);
            sessions.remove(session); // remove the session record
        }
    }

    public final ProxyNetConfig config;
    private final ProxyEventHandler handler;
    private final ConcurrentHashSet<Session> sessions = new ConcurrentHashSet<>();

    public Proxy(ProxyNetConfig config, ProxyEventHandler handler) {
        this.handler = handler;
        this.config = config;
    }

    public void handle() throws IOException {
        config.acceptLoop.addServer(config.server, null, new SessionServerHandler());
    }

    public void stop() {
        config.acceptLoop.removeServer(config.server);
    }

    public int sessionCount() {
        return sessions.size();
    }

    public void copySessions(Collection<? super Session> coll) {
        coll.addAll(sessions);
    }
}
