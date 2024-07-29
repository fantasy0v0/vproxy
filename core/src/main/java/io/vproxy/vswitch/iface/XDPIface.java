package io.vproxy.vswitch.iface;

import io.vproxy.base.selector.Handler;
import io.vproxy.base.selector.HandlerContext;
import io.vproxy.base.selector.SelectorEventLoop;
import io.vproxy.base.util.ByteArray;
import io.vproxy.base.util.Consts;
import io.vproxy.base.util.LogType;
import io.vproxy.base.util.Logger;
import io.vproxy.base.util.thread.VProxyThread;
import io.vproxy.pni.Allocator;
import io.vproxy.pni.array.PointerArray;
import io.vproxy.vfd.EventSet;
import io.vproxy.vpacket.AbstractPacket;
import io.vproxy.vpxdp.ChunkInfo;
import io.vproxy.vpxdp.XDPConsts;
import io.vproxy.vswitch.PacketBuffer;
import io.vproxy.vswitch.dispatcher.BPFMapKeySelector;
import io.vproxy.vswitch.util.SwitchUtils;
import io.vproxy.vswitch.util.UMemChunkByteArray;
import io.vproxy.xdp.*;

import java.io.IOException;
import java.lang.foreign.MemorySegment;

public class XDPIface extends Iface {
    public final String nic;
    public final BPFMap xskMap;
    public final BPFMap macMap;
    public final UMem umem;
    public final int rxRingSize;
    public final int txRingSize;
    public final BPFMode mode;
    public final boolean zeroCopy;
    public final int busyPollBudget;
    public final boolean rxGenChecksum;
    public final int queueId;

    private XDPSocket xsk;
    public final int vni;
    public final BPFMapKeySelector keySelector;
    public final boolean offload;
    private SelectorEventLoop loop;

    private final Allocator allocator;

    public XDPIface(String nic, BPFMap xskMap, BPFMap macMap, UMem umem,
                    int queue, int rxRingSize, int txRingSize, BPFMode mode, boolean zeroCopy,
                    int busyPollBudget, boolean rxGenChecksum,
                    int vni, BPFMapKeySelector keySelector, boolean offload) {
        // check offload
        if (offload) {
            if (macMap == null) {
                throw new IllegalArgumentException("offload is true, but macMap is not provided");
            }
        }

        this.nic = nic;
        this.xskMap = xskMap;
        this.macMap = macMap;
        this.umem = umem;
        this.rxRingSize = rxRingSize;
        this.txRingSize = txRingSize;
        this.mode = mode;
        this.zeroCopy = zeroCopy;
        this.busyPollBudget = busyPollBudget;
        this.rxGenChecksum = rxGenChecksum;
        this.queueId = queue;

        this.vni = vni;
        this.keySelector = keySelector;
        this.offload = offload;

        this.allocator = Allocator.ofUnsafe();
        this.sendingChunkPointers = new PointerArray(allocator, txRingSize);
    }

    @Override
    public void init(IfaceInitParams params) throws Exception {
        super.init(params);

        this.loop = params.loop;

        XDPSocket xsk;
        try {
            xsk = XDPSocket.create(nic, queueId, umem, rxRingSize, txRingSize, mode, zeroCopy, busyPollBudget, rxGenChecksum);
        } catch (IOException e) {
            Logger.error(LogType.SOCKET_ERROR, "creating xsk of " + nic + "#" + queueId + " failed", e);
            throw e;
        }
        this.xsk = xsk;

        try {
            params.loop.add(xsk, EventSet.read(), null, new XDPHandler());
        } catch (IOException e) {
            Logger.error(LogType.EVENT_LOOP_ADD_FAIL, "add xsk into loop failed", e);
            throw e;
        }

        int key = keySelector.select(xsk);
        xskMap.put(key, xsk);
    }

    private int sendingChunkSize = 0;
    private final PointerArray sendingChunkPointers;

    @Override
    public void sendPacket(PacketBuffer pkb) {
        if (sendingChunkSize == txRingSize) {
            completeTx();
        }

        if (pkb.fullbuf instanceof UMemChunkByteArray ub) {
            var chunk = ub.chunk;
            if (chunk.getUmem().MEMORY.address() == umem.umem.MEMORY.address()) {
                assert Logger.lowLevelDebug("directly send packet without copying");

                // modify chunk
                long pktaddr = chunk.getAddr() + pkb.pktOff;
                int pktlen = pkb.pktBuf.length();

                assert Logger.lowLevelDebug("update pktaddr(" + pktaddr + ") and pktlen(" + pktlen + ")");
                chunk.setPktAddr(pktaddr);
                chunk.setPktLen(pktlen);
                chunk.setCsumFlags(SwitchUtils.checksumFlagsFor(pkb.pkt, umem.metaLen));
                if (chunk.getCsumFlags() != 0) {
                    statistics.incrCsumSkip();
                }
                ub.reference();

                assert Logger.lowLevelDebug("directly write packet " + chunk + " without copying");
                sendingChunkPointers.set(sendingChunkSize++, chunk.MEMORY);

                statistics.incrTxPkts();
                statistics.incrTxBytes(pktlen);

                // stack generated packets won't have the opportunity to call completeTx
                // ensure the packet is transmitted
                if (!pkb.ifaceInput) {
                    completeTx();
                }
                return;
            }
        }
        assert Logger.lowLevelDebug("fetch a new chunk to send the packet");
        var chunk = umem.umem.getChunks().fetch();
        if (chunk == null) {
            assert Logger.lowLevelDebug("packet dropped because there are no free chunks available");
            statistics.incrTxErr();
            return;
        }
        ByteArray pktData = pkb.pkt.getRawPacket(AbstractPacket.FLAG_CHECKSUM_UNNECESSARY);

        long pktaddr = chunk.getAddr() + Consts.XDP_HEADROOM_DRIVER_RESERVED;
        long availableSpace = chunk.getEndAddr() - chunk.getAddr() - Consts.XDP_HEADROOM_DRIVER_RESERVED;
        var csumFlags = SwitchUtils.checksumFlagsFor(pkb.pkt, umem.metaLen);
        if ((csumFlags & XDPConsts.VP_CSUM_XDP_OFFLOAD) != 0) {
            pktaddr += umem.metaLen;
            availableSpace -= umem.metaLen;
        }

        if (pktData.length() > availableSpace) {
            Logger.warn(LogType.ALERT, "umem chunk too small for packet, pkt: " + pktData.length() + ", available: " + availableSpace);
            umem.umem.getChunks().releaseChunk(chunk);
            return;
        }
        chunk.setPktAddr(pktaddr);
        chunk.setPktLen(pktData.length());
        chunk.setCsumFlags(csumFlags);
        if (chunk.getCsumFlags() != 0) {
            statistics.incrCsumSkip();
        }
        var segBuf = MemorySegment.ofAddress(chunk.getUmem().getBuffer().address() + pktaddr).reinterpret(pktData.length());
        pktData.copyInto(ByteArray.from(segBuf), 0, 0, pktData.length());

        sendingChunkPointers.set(sendingChunkSize++, chunk.MEMORY);

        statistics.incrTxPkts();
        statistics.incrTxBytes(pktData.length());

        // stack generated packets won't have the opportunity to call completeTx
        // ensure the packet is transmitted
        if (!pkb.ifaceInput) {
            completeTx();
        }
    }

    @Override
    public void destroy() {
        if (isDestroyed()) {
            return;
        }
        super.destroy();

        var xsk = this.xsk;
        if (xsk == null) {
            return;
        }
        try {
            xsk.close();
        } catch (IOException e) {
            Logger.error(LogType.SOCKET_ERROR, "closing xsk failed", e);
        }
        loop.runOnLoop(() -> {
            this.xsk = null;
            try {
                loop.remove(xsk);
            } catch (Throwable ignore) {
            }
        });
        allocator.close();
    }

    public XDPSocket getXsk() {
        return xsk;
    }

    @Override
    public int getLocalSideVni(int hint) {
        return this.vni;
    }

    @Override
    public int getOverhead() {
        return 0;
    }

    @Override
    public void completeTx() {
        if (sendingChunkSize > 0) {
            int n = xsk.writePackets(sendingChunkSize, sendingChunkPointers);
            assert Logger.lowLevelDebug("write xdp packets " + sendingChunkSize + ", succeeded = " + n);
            if (n != sendingChunkSize) {
                for (int i = n; i < sendingChunkSize; ++i) {
                    var chunk = new ChunkInfo(sendingChunkPointers.get(i));
                    assert Logger.lowLevelDebug("writing chunk " + chunk + " failed, need to release them manually");
                    umem.umem.getChunks().releaseChunk(chunk);
                }
                statistics.incrTxErr(sendingChunkSize - n);
            }
            sendingChunkSize = 0; // reset
        }
        xsk.completeTx();
        xsk.umem.umem.fillRingFillup();
    }

    @Override
    public String name() {
        return "xdp:" + nic;
    }

    @Override
    protected String toStringExtra() {
        return "#q=" + queueId + ",umem=" + umem.alias + ",vni:" + vni + (offload ? ",offload" : "");
    }

    private class XDPHandler implements Handler<XDPSocket> {
        private XDPHandler() {
        }

        @Override
        public void accept(HandlerContext<XDPSocket> ctx) {
            // will not fire
        }

        @Override
        public void connected(HandlerContext<XDPSocket> ctx) {
            // will not fire
        }

        @Override
        public void readable(HandlerContext<XDPSocket> ctx) {
            VProxyThread.current().newUuidDebugInfo();

            var ls = ctx.getChannel().fetchPackets();
            if (ls.isEmpty()) {
                Logger.shouldNotHappen("xdp readable " + xsk + " but received nothing");
            } else {
                assert Logger.lowLevelDebug("xdp readable: " + xsk + ", chunks=" + ls.size());
            }
            for (var chunk : ls) {
                var fullBuffer = new UMemChunkByteArray(xsk, chunk);

                var pkb = PacketBuffer.fromEtherBytes(XDPIface.this, vni, fullBuffer,
                    (int) (chunk.getPktAddr() - chunk.getAddr()),
                    (int) (chunk.getEndAddr() - chunk.getPktAddr() - chunk.getPktLen()));

                String err = pkb.init();
                if (err != null) {
                    assert Logger.lowLevelDebug("got invalid packet: " + err);
                    fullBuffer.dereference();
                    statistics.incrRxErr();
                    continue;
                }

                statistics.incrRxPkts();
                statistics.incrRxBytes(chunk.getPktLen());

                received(pkb);
            }
            ctx.getChannel().rxRelease(ls.size());
            ls.clear();
            callback.alertPacketsArrive(XDPIface.this);
        }

        @Override
        public void writable(HandlerContext<XDPSocket> ctx) {
            // will not fire
        }

        @Override
        public void removed(HandlerContext<XDPSocket> ctx) {
            if (xsk == null) {
                return;
            }
            Logger.warn(LogType.CONN_ERROR, "xdp(queue=" + queueId + ") removed from loop, it's not handled anymore, need to be closed");
            try {
                xsk.close();
            } catch (IOException e) {
                Logger.shouldNotHappen("closing xsk failed", e);
            }
            callback.alertDeviceDown(XDPIface.this);
        }
    }
}
