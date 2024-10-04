package io.vproxy.app.controller;

import vjson.JSON;

import java.util.*;

public interface DockerNetworkDriver {
    String TEMPORARY_CONFIG_FILE = "/var/run/docker/.vproxy/vproxy.last";
    String PERSISTENT_CONFIG_FILE = "/x-etc/docker/.vproxy/vproxy.last";
    String PERSISTENT_SCRIPT = "/x-etc/docker/.vproxy/setup.sh";

    String VRF_OPTION = "docker-plugin.vproxy.io/network-vrf";
    String SUBNET4_OPTION = "docker-plugin.vproxy.io/network-subnet-v4";
    String SUBNET6_OPTION = "docker-plugin.vproxy.io/network-subnet-v6";

    void createNetwork(CreateNetworkRequest req) throws Exception;

    void deleteNetwork(String networkId) throws Exception;

    CreateEndpointResponse createEndpoint(CreateEndpointRequest req) throws Exception;

    void deleteEndpoint(String networkId, String endpointId) throws Exception;

    JoinResponse join(String networkId, String endpointId, String sandboxKey) throws Exception;

    void leave(String networkId, String endpointId) throws Exception;

    class CreateNetworkRequest {
        public String networkId;
        public List<IPData> ipv4Data;
        public List<IPData> ipv6Data;
        public JSON.Object options;
        public Map<String, String> optionsDockerNetworkGeneric; // com.docker.network.generic

        public static final String optionsDockerNetworkGenericKey = "com.docker.network.generic";

        public void initGenericOptions() {
            if (options.containsKey(optionsDockerNetworkGenericKey)) {
                var o = options.getObject(optionsDockerNetworkGenericKey);
                var m = new HashMap<String, String>();
                for (var key : o.keySet()) {
                    m.put(key, o.getString(key));
                }
                optionsDockerNetworkGeneric = m;
            } else {
                optionsDockerNetworkGeneric = Collections.emptyMap();
            }
        }

        @Override
        public String toString() {
            return "CreateNetworkRequest{" +
                "networkId='" + networkId + '\'' +
                ", ipv4Data=" + ipv4Data +
                ", ipv6Data=" + ipv6Data +
                ", options=" + options +
                '}';
        }
    }

    class IPData {
        public String addressSpace;
        public String pool;
        public String gateway;
        public Map<String, String> auxAddresses; // nullable

        String __transformedGateway;

        @Override
        public String toString() {
            return "IPData{" +
                "addressSpace='" + addressSpace + '\'' +
                ", pool='" + pool + '\'' +
                ", gateway='" + gateway + '\'' +
                ", auxAddresses=" + auxAddresses +
                '}';
        }
    }

    class CreateEndpointRequest {
        public String networkId;
        public String endpointId;
        public NetInterface netInterface; // nullable

        @Override
        public String toString() {
            return "CreateEndpointRequest{" +
                "networkId='" + networkId + '\'' +
                ", endpointId='" + endpointId + '\'' +
                ", netInterface=" + netInterface +
                '}';
        }
    }

    class NetInterface {
        public String address;
        public String addressIPV6;
        public String macAddress;

        @Override
        public String toString() {
            return "NetInterface{" +
                "address='" + address + '\'' +
                ", addressIPV6='" + addressIPV6 + '\'' +
                ", macAddress='" + macAddress + '\'' +
                '}';
        }
    }

    class CreateEndpointResponse {
        public NetInterface netInterface; // nullable

        @Override
        public String toString() {
            return "CreateEndpointResponse{" +
                "netInterface=" + netInterface +
                '}';
        }
    }

    class JoinResponse {
        public InterfaceName interfaceName = new InterfaceName();
        public String gateway;
        public String gatewayIPv6;
        public List<StaticRoute> staticRoutes = new ArrayList<>();

        @Override
        public String toString() {
            return "JoinResponse{" +
                "interfaceName=" + interfaceName +
                ", gateway='" + gateway + '\'' +
                ", gatewayIPv6='" + gatewayIPv6 + '\'' +
                ", staticRoutes=" + staticRoutes +
                '}';
        }
    }

    class InterfaceName {
        public String srcName;
        public String dstPrefix;

        @Override
        public String toString() {
            return "InterfaceName{" +
                "srcName='" + srcName + '\'' +
                ", dstPrefix='" + dstPrefix + '\'' +
                '}';
        }
    }

    class StaticRoute {
        public String destination;
        public int routeType; // 0: nextHop, 1: connected(no value for nextHop)
        public String nextHop;

        @Override
        public String toString() {
            return "StaticRoute{" +
                "destination='" + destination + '\'' +
                ", routeType=" + routeType +
                ", nextHop='" + nextHop + '\'' +
                '}';
        }
    }
}
