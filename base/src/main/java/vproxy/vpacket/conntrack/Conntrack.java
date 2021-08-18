package vproxy.vpacket.conntrack;

import vproxy.base.util.LogType;
import vproxy.base.util.Logger;
import vproxy.vfd.IP;
import vproxy.vfd.IPPort;
import vproxy.vfd.IPv4;
import vproxy.vpacket.conntrack.tcp.TcpEntry;
import vproxy.vpacket.conntrack.tcp.TcpListenEntry;
import vproxy.vpacket.conntrack.tcp.TcpListenHandler;
import vproxy.vpacket.conntrack.udp.UdpListenEntry;
import vproxy.vpacket.conntrack.udp.UdpListenHandler;

import java.util.*;

public class Conntrack {
    private final Map<IPPort, TcpListenEntry> tcpListenEntries = new HashMap<>();
    private final Map<IPPort, UdpListenEntry> udpListenEntries = new HashMap<>();
    // dstIPPort => srcIPPort => TcpEntry
    // make dstIPPort to be the first key for better performance
    private final Map<IPPort, Map<IPPort, TcpEntry>> tcpEntries = new HashMap<>();

    private static final IP ipv4BindAny = IP.from("0.0.0.0");
    private static final IP ipv6BindAny = IP.from("::");

    public int countListenEntry() {
        return tcpListenEntries.size();
    }

    public Collection<TcpListenEntry> listListenEntries() {
        return tcpListenEntries.values();
    }

    public int countTcpEntries() {
        int total = 0;
        for (var map : tcpEntries.values()) {
            total += map.size();
        }
        return total;
    }

    public Collection<TcpEntry> listTcpEntries() {
        List<TcpEntry> ls = new LinkedList<>();
        for (var map : tcpEntries.values()) {
            ls.addAll(map.values());
        }
        return ls;
    }

    public TcpListenEntry lookupTcpListen(IPPort dst) {
        var ret = tcpListenEntries.get(dst);
        if (ret != null) {
            return ret;
        }
        // search for wildcard
        if (dst.getAddress() instanceof IPv4) {
            return tcpListenEntries.get(new IPPort(ipv4BindAny, dst.getPort()));
        } else {
            return tcpListenEntries.get(new IPPort(ipv6BindAny, dst.getPort()));
        }
    }

    public UdpListenEntry lookupUdpListen(IPPort dst) {
        // wildcard is not allowed
        return udpListenEntries.get(dst);
    }

    public TcpEntry lookupTcp(IPPort src, IPPort dst) {
        var map = tcpEntries.get(dst);
        if (map == null) {
            return null;
        }
        return map.get(src);
    }

    public TcpEntry createTcp(TcpListenEntry listenEntry, IPPort src, IPPort dst, long seq) {
        var map = tcpEntries.computeIfAbsent(dst, x -> new HashMap<>());
        TcpEntry entry = new TcpEntry(listenEntry, src, dst, seq);
        var old = map.put(src, entry);
        if (old != null) {
            Logger.error(LogType.IMPROPER_USE, "found old connection " + old + " but a new connection with the same tuple is created");
            old.destroy();
        }
        return entry;
    }

    public TcpListenEntry listenTcp(IPPort dst, TcpListenHandler handler) {
        TcpListenEntry entry = new TcpListenEntry(dst, handler);
        var old = tcpListenEntries.put(dst, entry);
        if (old != null) {
            Logger.error(LogType.IMPROPER_USE, "found old listening entry " + old + " but trying to listen again");
            old.destroy();
        }
        return entry;
    }

    public UdpListenEntry listenUdp(IPPort dst, UdpListenHandler handler) {
        UdpListenEntry entry = new UdpListenEntry(dst, handler);
        var old = udpListenEntries.put(dst, entry);
        if (old != null) {
            Logger.error(LogType.IMPROPER_USE, "found old listening entry " + old + " but trying to listen again");
            old.destroy();
        }
        return entry;
    }

    public void removeTcpListen(IPPort dst) {
        tcpListenEntries.remove(dst);
    }

    public void removeUdpListen(IPPort dst) {
        udpListenEntries.remove(dst);
    }

    public void removeTcp(IPPort src, IPPort dst) {
        var map = tcpEntries.get(dst);
        if (map == null) {
            return;
        }
        map.remove(src);
        if (map.isEmpty()) {
            tcpEntries.remove(dst);
        }
    }
}
