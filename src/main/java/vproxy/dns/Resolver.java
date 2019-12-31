package vproxy.dns;

import vproxy.util.*;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.stream.Collectors;

public interface Resolver {
    void resolve(String host, Callback<? super InetAddress, ? super UnknownHostException> cb);

    void resolve(String host, boolean ipv4, boolean ipv6, Callback<? super InetAddress, ? super UnknownHostException> cb);

    void resolveV6(String host, Callback<? super Inet6Address, ? super UnknownHostException> cb);

    void resolveV4(String host, Callback<? super Inet4Address, ? super UnknownHostException> cb);

    default InetAddress blockResolve(String host) throws UnknownHostException {
        BlockCallback<InetAddress, UnknownHostException> cb = new BlockCallback<>();
        resolve(host, cb);
        return cb.block();
    }

    int cacheCount();

    void copyCache(Collection<? super Cache> cacheList);

    static Resolver getDefault() {
        return AbstractResolver.getDefault();
    }

    static void stopDefault() {
        AbstractResolver.stopDefault();
    }

    void addListener(ResolveListener listener);

    void clearCache();

    void start();

    void stop() throws IOException;

    static List<InetSocketAddress> getNameServers() {
        List<InetSocketAddress> ret = getNameServersFromFile();
        if (ret.isEmpty()) {
            Logger.alert("using 8.8.8.8 and 8.8.4.4 as name servers");
            ret.add(new InetSocketAddress(Utils.l3addr(new byte[]{8, 8, 8, 8}), 53));
            ret.add(new InetSocketAddress(Utils.l3addr(new byte[]{8, 8, 4, 4}), 53));
        }
        return ret;
    }

    private static List<InetSocketAddress> getNameServersFromFile() {
        // try ~/resolv.conf for customized resolve configuration
        File f = new File(Utils.homefile("resolv.conf"));
        if (!f.exists() || !f.isFile()) { // try linux|bsd resolve configuration
            f = new File("/etc/resolv.conf");
        }
        if (!f.exists() || !f.isFile()) { // still not found
            return Collections.emptyList();
        }
        FileInputStream stream;
        try {
            stream = new FileInputStream(f);
        } catch (FileNotFoundException e) {
            Logger.shouldNotHappen("still getting FileNotFoundException while the file existence is already checked: " + f, e);
            return Collections.emptyList();
        }
        Logger.alert("trying to get name servers from " + f.getAbsolutePath());
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(stream));
            List<InetSocketAddress> ret = new ArrayList<>();
            List<InetSocketAddress> unreachable = new ArrayList<>();
            while (true) {
                String line;
                try {
                    if ((line = br.readLine()) == null) break;
                } catch (IOException e) {
                    Logger.shouldNotHappen("reading " + f + " got exception", e);
                    return ret;
                }
                if (line.contains("#")) {
                    line = line.substring(0, line.indexOf("#")); // remove comment
                }
                line = line.trim();
                if (line.startsWith("nameserver ")) {
                    line = line.substring("nameserver ".length());
                } else {
                    continue;
                }
                if (Utils.isIpLiteral(line)) {
                    InetSocketAddress addr = new InetSocketAddress(Utils.l3addr(line), 53);
                    // need to remove localhost addresses because it might be vproxy itself
                    {
                        String ipName = Utils.ipStr(addr.getAddress().getAddress());
                        if (ipName.startsWith("127.") ||
                            ipName.equals("[0000:0000:0000:0000:0000:0000:0000:0001]") || // only one ipv6 loopback address
                            ipName.startsWith("[0000:0000:0000:0000:0000:ffff:7f]") || // v4-mapped v6
                            ipName.startsWith("[0000:0000:0000:0000:0000:0000:7f]")) { // v4-compatible v6
                            continue;
                        }
                    }
                    // need to check whether it's reachable
                    {
                        boolean reachable;
                        try {
                            reachable = addr.getAddress().isReachable(100);
                        } catch (IOException e) {
                            Logger.error(LogType.SYS_ERROR, "got error when trying to test whether " + Utils.ipStr(addr.getAddress().getAddress()) + " is reachable");
                            continue;
                        }
                        if (!reachable) {
                            unreachable.add(addr);
                            continue;
                        }
                    }

                    ret.add(addr);
                } else {
                    Logger.warn(LogType.INVALID_EXTERNAL_DATA, f + " contains invalid nameserver config: " + line);
                }
            }
            if (!unreachable.isEmpty()) {
                Logger.warn(LogType.ALERT, "some endpoints are unreachable and removed from the name server list: " + unreachable);
            }
            return ret;
        } finally {
            try {
                stream.close();
            } catch (IOException ignore) {
            }
        }
    }

    static Map<String, InetAddress> getHosts() {
        // try ~/hosts for customized host config
        File f = new File(Utils.homefile("hosts"));
        if (!f.exists() || !f.isFile()) { // try linux|bsd host file
            f = new File("/etc/hosts");
        }
        if (!f.exists() || !f.isFile()) { // try windows host file
            f = new File("c:\\Windows\\System32\\Drivers\\etc\\hosts");
        }
        if (!f.exists() || !f.isFile()) {
            return Collections.emptyMap();
        }
        FileInputStream stream;
        try {
            stream = new FileInputStream(f);
        } catch (FileNotFoundException e) {
            Logger.shouldNotHappen("still getting FileNotFoundException while the file existence is already checked: " + f, e);
            return Collections.emptyMap();
        }
        Logger.alert("trying to get hosts from " + f.getAbsolutePath());
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(stream));
            Map<String, InetAddress> ret = new HashMap<>();
            while (true) {
                String line;
                try {
                    if ((line = br.readLine()) == null) break;
                } catch (IOException e) {
                    Logger.shouldNotHappen("reading " + f + " got exception", e);
                    return ret;
                }
                if (line.contains("#")) {
                    line = line.substring(0, line.indexOf("#")); // remove comment
                }
                if (line.isBlank()) {
                    continue; // ignore empty line or lines with only comment in it
                }
                line = line.trim();
                List<String> split = Arrays.asList(line.split("[ \\t]"));
                split = split.stream().map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
                if (split.size() < 2) {
                    Logger.warn(LogType.INVALID_EXTERNAL_DATA, f + " contains invalid host config: " + line);
                    continue;
                }
                String ip = split.get(0);
                byte[] ipBytes = Utils.parseIpString(ip);
                if (ipBytes == null) {
                    Logger.warn(LogType.INVALID_EXTERNAL_DATA, f + " contains invalid host config: not ip: " + line);
                    continue;
                }
                InetAddress l3addr = Utils.l3addr(ipBytes);
                for (int i = 1; i < split.size(); ++i) {
                    String domain1 = split.get(i);
                    String domain2;
                    if (domain1.endsWith(".")) {
                        domain2 = domain1.substring(0, domain1.length() - 1);
                    } else {
                        domain2 = domain1 + ".";
                    }
                    if (ret.containsKey(domain1) || ret.containsKey(domain2)) { // only consider the first present domain
                        continue;
                    }
                    ret.put(domain1, l3addr);
                    ret.put(domain2, l3addr);
                }
            }
            return ret;
        } finally {
            try {
                stream.close();
            } catch (IOException ignore) {
            }
        }
    }
}
