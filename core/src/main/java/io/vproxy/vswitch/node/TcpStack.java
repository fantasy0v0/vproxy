package io.vproxy.vswitch.node;

import io.vproxy.base.util.ByteArray;
import io.vproxy.base.util.Consts;
import io.vproxy.base.util.Logger;
import io.vproxy.base.util.thread.VProxyThread;
import io.vproxy.commons.graph.GraphBuilder;
import io.vproxy.vpacket.AbstractIpPacket;
import io.vproxy.vpacket.TcpPacket;
import io.vproxy.vpacket.conntrack.tcp.Segment;
import io.vproxy.vpacket.conntrack.tcp.TcpEntry;
import io.vproxy.vpacket.conntrack.tcp.TcpState;
import io.vproxy.vpacket.conntrack.tcp.TcpUtils;
import io.vproxy.vswitch.PacketBuffer;
import io.vproxy.vswitch.SwitchDelegate;
import io.vproxy.vswitch.VirtualNetwork;

import java.util.List;

@SuppressWarnings("ConstantConditions")
public class TcpStack extends Node {
    private final SwitchDelegate sw;
    private final NodeEgress tcpReset = new NodeEgress("tcp-reset");
    private final NodeEgress l4output = new NodeEgress("l4-output");

    public TcpStack(SwitchDelegate sw) {
        super("tcp-stack");
        this.sw = sw;
    }

    @Override
    protected void initGraph(GraphBuilder<Node> builder) {
        builder.addEdge("tcp-stack", "tcp-reset", "tcp-reset", DEFAULT_EDGE_DISTANCE);
        builder.addEdge("tcp-stack", "l4-output", "l4-output", DEFAULT_EDGE_DISTANCE);
    }

    @Override
    protected void initNode() {
        fillEdges(tcpReset);
        fillEdges(l4output);
    }

    @Override
    protected HandleResult preHandle(PacketBuffer pkb) {
        return HandleResult.PASS;
    }

    @Override
    protected HandleResult handle(PacketBuffer pkb, NodeGraphScheduler scheduler) {
        var tcp = pkb.tcp;
        if (pkb.debugger.isDebugOn()) {
            pkb.debugger.line(d -> d.append("tcp state ").append(tcp.getState()));
        }
        switch (tcp.getState()) {
            case CLOSED:
                return handleTcpClosed(pkb);
            case SYN_SENT:
                return handleTcpSynSent(pkb);
            case SYN_RECEIVED:
                return handleTcpSynReceived(pkb);
            case ESTABLISHED:
                return handleTcpEstablished(pkb);
            case FIN_WAIT_1:
                return handleTcpFinWait1(pkb);
            case FIN_WAIT_2:
                return handleTcpFinWait2(pkb);
            case CLOSE_WAIT:
                return handleTcpCloseWait(pkb);
            case CLOSING:
                return handleTcpClosing(pkb);
            case LAST_ACK:
                return handleLastAck(pkb);
            case TIME_WAIT:
                return handleTimeWait(pkb);
            default:
                Logger.shouldNotHappen("should not reach here");
                if (pkb.debugger.isDebugOn()) {
                    pkb.debugger.line(d -> d.append("unexpected tcp state ").append(tcp.getState()));
                }
                return _returndrop(pkb);
        }
    }

    private TcpPacket buildSyn(TcpEntry tcp) {
        TcpPacket pkt = TcpUtils.buildCommonTcpResponse(tcp);
        pkt.setFlags(Consts.TCP_FLAGS_SYN);
        buildSynCommon(tcp, pkt);
        return pkt;
    }

    private TcpPacket buildSynAck(PacketBuffer pkb) {
        TcpPacket respondTcp = TcpUtils.buildCommonTcpResponse(pkb.tcp);
        respondTcp.setFlags(Consts.TCP_FLAGS_SYN | Consts.TCP_FLAGS_ACK);
        buildSynCommon(pkb.tcp, respondTcp);
        return respondTcp;
    }

    private void buildSynCommon(TcpEntry tcp, TcpPacket respondTcp) {
        respondTcp.setWindow(65535);
        {
            var optMss = new TcpPacket.TcpOption(respondTcp);
            optMss.setKind(Consts.TCP_OPTION_MSS);
            optMss.setData(ByteArray.allocate(2).int16(0, TcpEntry.RCV_MSS));
            respondTcp.getOptions().add(optMss);
        }
        {
            int scale = tcp.receivingQueue.getWindowScale();
            int cnt = 0;
            while (scale != 1) {
                scale /= 2;
                cnt += 1;
            }
            if (cnt != 0) {
                var optWindowScale = new TcpPacket.TcpOption(respondTcp);
                optWindowScale.setKind(Consts.TCP_OPTION_WINDOW_SCALE);
                optWindowScale.setData(ByteArray.allocate(1).set(0, (byte) cnt));
                respondTcp.getOptions().add(optWindowScale);
            }
        }
    }

    private HandleResult handleTcpClosed(PacketBuffer pkb) {
        assert Logger.lowLevelDebug("handleTcpClosed");

        var tcpPkt = pkb.tcpPkt;
        // only handle syn
        if (tcpPkt.getFlags() != Consts.TCP_FLAGS_SYN) {
            assert Logger.lowLevelDebug("not SYN packet");
            if (pkb.debugger.isDebugOn()) {
                pkb.debugger.line(d -> d.append("not SYN packet"));
            }
            return _returndrop(pkb);
        }
        if (pkb.ensurePartialPacketParsed()) {
            if (pkb.debugger.isDebugOn()) {
                pkb.debugger.line(d -> d.append("invalid packet"));
            }
            return _returndropSkipErrorDrop();
        }

        pkb.tcp.setState(TcpState.SYN_RECEIVED);
        initTcp(pkb.tcp, pkb.tcpPkt);

        // SYN-ACK
        TcpPacket respondTcp = buildSynAck(pkb);
        AbstractIpPacket respondIp = TcpUtils.buildIpResponse(pkb.tcp, respondTcp);

        pkb.tcp.sendingQueue.incAllSeq();

        pkb.replacePacket(respondIp);
        return _returnnext(pkb, l4output);
    }

    private void initTcp(TcpEntry tcp, TcpPacket tcpPkt) {
        // get tcp options from the syn
        int mss = TcpEntry.SND_DEFAULT_MSS;
        int windowScale = 1;
        for (var opt : tcpPkt.getOptions()) {
            switch (opt.getKind()) {
                case Consts.TCP_OPTION_MSS:
                    mss = opt.getData().uint16(0);
                    break;
                case Consts.TCP_OPTION_WINDOW_SCALE:
                    int s = opt.getData().uint8(0);
                    windowScale = 1 << s;
                    break;
            }
        }
        tcp.sendingQueue.init(tcpPkt.getWindow(), mss, windowScale);
    }

    private HandleResult handleTcpSynSent(PacketBuffer pkb) {
        var tcpPkt = pkb.tcpPkt;
        if (tcpPkt.isSyn() && tcpPkt.isAck()) {
            // is syn-ack packet
            assert Logger.lowLevelDebug("syn-ack received");
            if (tcpPkt.getAckNum() == pkb.tcp.sendingQueue.getAckSeq()) {
                assert Logger.lowLevelDebug("seq matches");
                if (pkb.tcp.retransmissionTimer != null) {
                    pkb.tcp.retransmissionTimer.cancel();
                    pkb.tcp.retransmissionTimer = null;
                }
                pkb.tcp.receivingQueue.setInitialSeq(tcpPkt.getSeqNum() + 1);
                initTcp(pkb.tcp, pkb.tcpPkt);
                connectionEstablishes(pkb);
                var ack = TcpUtils.buildAckResponse(pkb.tcp);
                var ipPkt = TcpUtils.buildIpResponse(pkb.tcp, ack);
                pkb.replacePacket(ipPkt);
                return _returnnext(pkb, l4output);
            } else {
                assert Logger.lowLevelDebug("received packet ack doesn't match sending seq");
            }
        } else {
            assert Logger.lowLevelDebug("received packet is not syn-ack");
        }
        return _returndrop(pkb);
    }

    private HandleResult handleTcpSynReceived(PacketBuffer pkb) {
        assert Logger.lowLevelDebug("handleTcpSynReceived");
        // first check whether the packet has ack, and if so, check the ack number
        var tcpPkt = pkb.tcpPkt;
        if (tcpPkt.isSyn()) {
            assert Logger.lowLevelDebug("probably a syn retransmission");
            if (tcpPkt.getSeqNum() == pkb.tcp.receivingQueue.getAckedSeq() - 1) {
                assert Logger.lowLevelDebug("seq matches");
                pkb.tcp.sendingQueue.decAllSeq();
                TcpPacket respondTcp = buildSynAck(pkb);
                AbstractIpPacket respondIp = TcpUtils.buildIpResponse(pkb.tcp, respondTcp);
                pkb.tcp.sendingQueue.incAllSeq();
                pkb.replacePacket(respondIp);
                return _returnnext(pkb, l4output);
            }
        }
        if (!tcpPkt.isAck()) {
            assert Logger.lowLevelDebug("no ack flag set");
            if (pkb.debugger.isDebugOn()) {
                pkb.debugger.line(d -> d.append("no ack flag"));
            }
            return _returndrop(pkb);
        }
        if (tcpPkt.getAckNum() != pkb.tcp.sendingQueue.getAckSeq()) {
            assert Logger.lowLevelDebug("wrong ack number");
            if (pkb.debugger.isDebugOn()) {
                pkb.debugger.line(d -> d.append("wrong ack number"));
            }
            return _returndrop(pkb);
        }
        connectionEstablishes(pkb);

        // then run the same handling as established
        return handleTcpEstablished(pkb);
    }

    private void connectionEstablishes(PacketBuffer pkb) {
        assert Logger.lowLevelDebug("connectionEstablishes");
        pkb.tcp.setState(TcpState.ESTABLISHED);
        // alert that this connection can be retrieved
        var parent = pkb.tcp.getParent();
        if (parent == null) {
            return;
        }
        parent.synBacklog.remove(pkb.tcp);
        parent.backlog.add(pkb.tcp);
        parent.listenHandler.readable(parent);
    }

    private boolean handleTcpGeneralReturnFalse(PacketBuffer pkb) {
        assert Logger.lowLevelDebug("handleTcpGeneral");

        var tcpPkt = pkb.tcpPkt;

        // check whether seq matches
        var seq = tcpPkt.getSeqNum();
        var expect = pkb.tcp.receivingQueue.getExpectingSeq();
        var acked = pkb.tcp.receivingQueue.getAckedSeq();
        if (tcpPkt.isFin()) {
            if (seq != acked) {
                assert Logger.lowLevelDebug("data not fully consumed yet but received FIN");
                if (pkb.debugger.isDebugOn()) {
                    pkb.debugger.line(d -> d.append("data not fully consumed yet but received FIN"));
                }
                return true;
            }
        } else if (seq != expect) {
            if (!tcpPkt.isPsh() || seq > expect) {
                assert Logger.lowLevelDebug("invalid sequence number");
                if (pkb.debugger.isDebugOn()) {
                    pkb.debugger.line(d -> d.append("invalid sequence number"));
                }
                return true;
            }
        }

        if (tcpPkt.isAck()) {
            long ack = tcpPkt.getAckNum();
            int window = tcpPkt.getWindow();
            pkb.tcp.sendingQueue.ack(ack, window);
            // then check whether there's data to send
            // because the window may forbid it from sending
            // ack resets the window so it might get chance to send data
            if (pkb.tcp.retransmissionTimer == null) {
                _tcpStartRetransmission(pkb.network, pkb.tcp);
            }
        }
        return false;
    }

    private HandleResult handleTcpEstablished(PacketBuffer pkb) {
        assert Logger.lowLevelDebug("handleTcpEstablished");
        if (handleTcpGeneralReturnFalse(pkb)) {
            return _returndrop(pkb);
        }
        if (pkb.tcpPkt.isSyn() && pkb.tcpPkt.isAck()) {
            assert Logger.lowLevelDebug("received syn-ack, probably a retransmission");
            var respondTcp = TcpUtils.buildAckResponse(pkb.tcp);
            var respondIp = TcpUtils.buildIpResponse(pkb.tcp, respondTcp);
            pkb.replacePacket(respondIp);
            return _returnnext(pkb, l4output);
        }
        var tcpPkt = pkb.tcpPkt;
        if (tcpPkt.isPsh()) {
            long seq = tcpPkt.getSeqNum();
            ByteArray data = tcpPkt.getData();
            pkb.tcp.receivingQueue.store(new Segment(seq, data));
        }
        if (tcpPkt.isFin()) {
            pkb.tcp.setState(TcpState.CLOSE_WAIT);
            pkb.tcp.receivingQueue.incExpectingSeq();
            _tcpAck(pkb.network, pkb.tcp);
            return _return(HandleResult.STOLEN, pkb);
        }
        return _return(HandleResult.STOLEN, pkb);
    }

    private HandleResult handleTcpFinWait1(PacketBuffer pkb) {
        assert Logger.lowLevelDebug("handleTcpFinWait1");
        if (handleTcpGeneralReturnFalse(pkb)) {
            return _returndrop(pkb);
        }
        var tcpPkt = pkb.tcpPkt;
        if (tcpPkt.isFin()) {
            if (pkb.tcp.sendingQueue.ackOfFinReceived()) {
                assert Logger.lowLevelDebug("transform to CLOSING");
                pkb.tcp.setState(TcpState.CLOSING);
                return _returnnext(pkb, tcpReset);
            } else {
                assert Logger.lowLevelDebug("received FIN but the previous sent FIN not acked");
            }
        } else {
            if (pkb.tcp.sendingQueue.ackOfFinReceived()) {
                assert Logger.lowLevelDebug("the sent FIN is acked, transform to FIN_WAIT_2");
                pkb.tcp.setState(TcpState.FIN_WAIT_2);
            }
        }
        return _return(HandleResult.STOLEN, pkb);
    }

    private HandleResult handleTcpFinWait2(PacketBuffer pkb) {
        assert Logger.lowLevelDebug("handleTcpFinWait2");
        if (handleTcpGeneralReturnFalse(pkb)) {
            return _returndrop(pkb);
        }
        var tcpPkt = pkb.tcpPkt;
        if (tcpPkt.isFin()) {
            assert Logger.lowLevelDebug("transform to CLOSING");
            pkb.tcp.setState(TcpState.CLOSING);
            return _returnnext(pkb, tcpReset);
        }
        return _return(HandleResult.STOLEN, pkb);
    }

    private HandleResult handleTcpCloseWait(PacketBuffer pkb) {
        assert Logger.lowLevelDebug("handleTcpCloseWait");
        if (handleTcpGeneralReturnFalse(pkb)) {
            return _returndrop(pkb);
        }
        var tcpPkt = pkb.tcpPkt;
        if (tcpPkt.isFin()) {
            assert Logger.lowLevelDebug("received FIN again, maybe it's retransmission");
            if (tcpPkt.getSeqNum() == pkb.tcp.receivingQueue.getExpectingSeq() - 1) {
                _tcpAck(pkb.network, pkb.tcp);
                return _return(HandleResult.STOLEN, pkb);
            }
        }
        return _return(HandleResult.STOLEN, pkb);
    }

    private HandleResult handleTcpClosing(PacketBuffer pkb) {
        assert Logger.lowLevelDebug("handleTcpClosing");
        if (handleTcpGeneralReturnFalse(pkb)) {
            return _returndrop(pkb);
        }
        assert Logger.lowLevelDebug("drop any packet when it's in CLOSING state");
        return _return(HandleResult.STOLEN, pkb);
    }

    private HandleResult handleLastAck(@SuppressWarnings("unused") PacketBuffer pkb) {
        Logger.shouldNotHappen("unsupported yet: last-ack state");
        return _returndrop(pkb);
    }

    private HandleResult handleTimeWait(@SuppressWarnings("unused") PacketBuffer pkb) {
        Logger.shouldNotHappen("unsupported yet: time-wait state");
        return _returndrop(pkb);
    }

    private void _tcpAck(VirtualNetwork network, TcpEntry tcp) {
        assert Logger.lowLevelDebug("tcpAck(" + ", " + network + ", " + tcp + ")");

        if (tcp.receivingQueue.getWindow() == 0) {
            assert Logger.lowLevelDebug("no window, very bad, need to ack immediately");
            if (tcp.delayedAckTimer != null) {
                assert Logger.lowLevelDebug("cancel the timer");
                tcp.delayedAckTimer.cancel();
                tcp.delayedAckTimer = null;
            }
            sendAck(network, tcp);
            return;
        }
        if (tcp.delayedAckTimer != null) {
            assert Logger.lowLevelDebug("delayed ack already scheduled");
            return;
        }
        tcp.delayedAckTimer = sw.getSelectorEventLoop().delay(TcpEntry.DELAYED_ACK_TIMEOUT, () -> sendAck(network, tcp));
    }

    public void tcpAck(VirtualNetwork network, TcpEntry tcp) {
        VProxyThread.current().newUuidDebugInfo();
        _tcpAck(network, tcp);
    }

    private void sendAck(VirtualNetwork network, TcpEntry tcp) {
        VProxyThread.current().newUuidDebugInfo();
        assert Logger.lowLevelDebug("sendAck(" + ", " + network + ", " + tcp + ")");

        if (tcp.delayedAckTimer != null) {
            tcp.delayedAckTimer.cancel();
            tcp.delayedAckTimer = null;
        }

        TcpPacket respondTcp = TcpUtils.buildAckResponse(tcp);
        AbstractIpPacket respondIp = TcpUtils.buildIpResponse(tcp, respondTcp);

        PacketBuffer pkb = PacketBuffer.fromPacket(network, respondIp);
        pkb.tcp = tcp;
        _output(pkb);
    }

    private void _tcpStartRetransmission(VirtualNetwork network, TcpEntry tcp) {
        assert Logger.lowLevelDebug("tcpStartRetransmission(" + network + "," + tcp + ")");
        transmitTcp(network, tcp, 0, 0);
    }

    public void tcpStartRetransmission(VirtualNetwork network, TcpEntry tcp) {
        VProxyThread.current().newUuidDebugInfo();
        _tcpStartRetransmission(network, tcp);
    }

    private void transmitTcp(VirtualNetwork network, TcpEntry tcp, long lastBeginSeq, int retransmissionCount) {
        assert Logger.lowLevelDebug("transmitTcp(" + network + "," + tcp + ")");

        if (tcp.retransmissionTimer != null) { // reset timer
            tcp.retransmissionTimer.cancel();
            tcp.retransmissionTimer = null;
        }

        // check whether need to reset the connection because of too many retransmits
        if (tcp.requireClosing() && retransmissionCount > TcpEntry.MAX_RETRANSMISSION_AFTER_CLOSING) {
            assert Logger.lowLevelDebug("conn " + tcp + " is closed due to too many retransmission after closing");
            _resetTcpConnection(network, tcp);
            return;
        }

        assert Logger.lowLevelDebug("current tcp state is " + tcp.getState());
        if (tcp.getState() == TcpState.CLOSED || tcp.getState() == TcpState.SYN_SENT) {
            transmitTcpSyn(network, tcp, retransmissionCount);
        } else {
            transmitTcpPsh(network, tcp, lastBeginSeq, retransmissionCount);
        }
    }

    private void transmitTcpSyn(VirtualNetwork network, TcpEntry tcp, int retransmissionCount) {
        tcp.setState(TcpState.SYN_SENT);
        sendTcpSyn(network, tcp);
        setRetransmitTimer(network, tcp, 0, retransmissionCount);
    }

    private void transmitTcpPsh(VirtualNetwork network, TcpEntry tcp, long lastBeginSeq, int retransmissionCount) {
        List<Segment> segments = tcp.sendingQueue.fetch();
        if (segments.isEmpty()) { // no data to send, check FIN
            if (tcp.sendingQueue.needToSendFin()) {
                assert Logger.lowLevelDebug("need to send FIN");
                // fall through
            } else {
                // nothing to send
                assert Logger.lowLevelDebug("no need to retransmit after " + retransmissionCount + " time(s)");
                if (tcp.retransmissionTimer != null) {
                    tcp.retransmissionTimer.cancel();
                    tcp.retransmissionTimer = null;
                }
                afterTransmission(network, tcp);
                return;
            }
        }
        long currentBeginSeq = segments.isEmpty() ? tcp.sendingQueue.getFetchSeq() + 1 : segments.get(0).seqBeginInclusive;
        if (currentBeginSeq != lastBeginSeq) {
            assert Logger.lowLevelDebug("the sequence increased, it's not retransmitting after " + retransmissionCount + " time(s)");
            retransmissionCount = 0;
        }

        // initiate timer
        setRetransmitTimer(network, tcp, currentBeginSeq, retransmissionCount);

        if (segments.isEmpty()) {
            assert tcp.sendingQueue.needToSendFin();
            sendTcpFin(network, tcp);
        } else {
            for (var s : segments) {
                sendTcpPsh(network, tcp, s);
            }
        }
    }

    private void setRetransmitTimer(VirtualNetwork network, TcpEntry tcp, long currentBeginSeq, int retransmissionCount) {
        int delay = TcpEntry.RTO_MIN << retransmissionCount;
        if (delay <= 0 || delay > TcpEntry.RTO_MAX) { // overflow or exceeds maximum
            delay = TcpEntry.RTO_MAX;
        }
        assert Logger.lowLevelDebug("will delay " + delay + " ms then retransmit");
        final int finalRetransmissionCount = retransmissionCount;
        tcp.retransmissionTimer = sw.getSelectorEventLoop().delay(delay, () ->
            transmitTcp(network, tcp, currentBeginSeq, finalRetransmissionCount + 1)
        );
    }

    private void afterTransmission(VirtualNetwork network, TcpEntry tcp) {
        assert Logger.lowLevelDebug("afterTransmission(" + network + "," + tcp + "," + ")");

        if (tcp.requireClosing()) {
            assert Logger.lowLevelDebug("need to be closed");
            _resetTcpConnection(network, tcp);
        }
    }

    private void _resetTcpConnection(VirtualNetwork network, TcpEntry tcp) {
        assert Logger.lowLevelDebug("resetTcpConnection(" + network + "," + tcp + "," + ")");

        PacketBuffer pkb = PacketBuffer.fromPacket(network, TcpUtils.buildIpResponse(tcp, TcpUtils.buildRstResponse(tcp)));
        pkb.tcp = tcp;
        _output(pkb);

        tcp.setState(TcpState.CLOSED);
        network.conntrack.removeTcp(tcp.remote, tcp.local);
    }

    public void resetTcpConnection(VirtualNetwork network, TcpEntry tcp) {
        VProxyThread.current().newUuidDebugInfo();
        _resetTcpConnection(network, tcp);
    }

    private void sendTcpSyn(VirtualNetwork network, TcpEntry tcp) {
        tcp.sendingQueue.decAllSeq();
        var tcpPkt = buildSyn(tcp);
        AbstractIpPacket ipPkt = TcpUtils.buildIpResponse(tcp, tcpPkt);
        tcp.sendingQueue.incAllSeq();

        PacketBuffer pkb = PacketBuffer.fromPacket(network, ipPkt);
        pkb.tcp = tcp;
        _output(pkb);
    }

    private void sendTcpPsh(VirtualNetwork network, TcpEntry tcp, Segment s) {
        VProxyThread.current().newUuidDebugInfo();
        assert Logger.lowLevelDebug("sendTcpPsh(" + network + "," + tcp + "," + s + ")");

        TcpPacket tcpPkt = TcpUtils.buildCommonTcpResponse(tcp);
        tcpPkt.setSeqNum(s.seqBeginInclusive);
        tcpPkt.setFlags(Consts.TCP_FLAGS_PSH | Consts.TCP_FLAGS_ACK);
        tcpPkt.setData(s.data);
        AbstractIpPacket ipPkt = TcpUtils.buildIpResponse(tcp, tcpPkt);

        PacketBuffer pkb = PacketBuffer.fromPacket(network, ipPkt);
        pkb.tcp = tcp;
        _output(pkb);
    }

    private void sendTcpFin(VirtualNetwork network, TcpEntry tcp) {
        VProxyThread.current().newUuidDebugInfo();
        assert Logger.lowLevelDebug("sendTcpFin(" + network + "," + tcp + ")");

        TcpPacket tcpPkt = TcpUtils.buildCommonTcpResponse(tcp);
        tcpPkt.setSeqNum(tcp.sendingQueue.getFetchSeq());
        tcpPkt.setFlags(Consts.TCP_FLAGS_FIN | Consts.TCP_FLAGS_ACK);
        AbstractIpPacket ipPkt = TcpUtils.buildIpResponse(tcp, tcpPkt);

        PacketBuffer pkb = PacketBuffer.fromPacket(network, ipPkt);
        pkb.tcp = tcp;
        _output(pkb);
    }

    private void _output(PacketBuffer pkb) {
        _schedule(sw.scheduler, pkb, l4output);
    }

    public void output(PacketBuffer pkb) {
        VProxyThread.current().newUuidDebugInfo();
        _output(pkb);
    }
}
