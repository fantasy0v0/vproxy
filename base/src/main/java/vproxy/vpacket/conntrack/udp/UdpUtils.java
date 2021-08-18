package vproxy.vpacket.conntrack.udp;

import vproxy.base.util.ByteArray;
import vproxy.base.util.Consts;
import vproxy.vfd.IPv4;
import vproxy.vfd.IPv6;
import vproxy.vpacket.*;

import java.util.Collections;

public class UdpUtils {
    private UdpUtils() {
    }

    public static UdpPacket buildCommonUdpResponse(UdpListenEntry udp, Datagram dg) {
        var ret = new UdpPacket();
        ret.setSrcPort(udp.bind.getPort());
        ret.setDstPort(dg.remotePort);
        ret.setLength(8 + dg.data.length());
        ret.setData(new PacketBytes(dg.data));

        return ret;
    }

    public static AbstractIpPacket buildIpResponse(UdpListenEntry udp, Datagram dg, UdpPacket udpPkt) {
        if (udp.bind.getAddress() instanceof IPv4) {
            var ipv4 = new Ipv4Packet();
            ipv4.setSrc((IPv4) udp.bind.getAddress());
            ipv4.setDst((IPv4) dg.remoteIp);
            var udpBytes = udpPkt.buildIPv4UdpPacket(ipv4);

            ipv4.setVersion(4);
            ipv4.setIhl(5);
            ipv4.setTotalLength(20 + udpBytes.length());
            ipv4.setTtl(64);
            ipv4.setProtocol(Consts.IP_PROTOCOL_UDP);
            ipv4.setOptions(ByteArray.allocate(0));

            ipv4.setPacket(udpPkt);
            return ipv4;
        } else {
            var ipv6 = new Ipv6Packet();
            ipv6.setSrc((IPv6) udp.bind.getAddress());
            ipv6.setDst((IPv6) dg.remoteIp);
            var udpBytes = udpPkt.buildIPv6UdpPacket(ipv6);

            ipv6.setVersion(6);
            ipv6.setNextHeader(Consts.IP_PROTOCOL_UDP);
            ipv6.setPayloadLength(udpBytes.length());
            ipv6.setHopLimit(64);
            ipv6.setExtHeaders(Collections.emptyList());

            ipv6.setPacket(udpPkt);
            return ipv6;
        }
    }
}
