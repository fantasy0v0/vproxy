package io.vproxy.vswitch.iface;

import io.vproxy.vfd.IPPort;
import io.vproxy.vswitch.PacketBuffer;

import java.util.Objects;

public class BareVXLanIface extends AbstractBaseSwitchSocketIface implements LocalSideVrfGetterSetter {
    public final IPPort udpSockAddress; // remote vxlan address
    private int localSideVrf;

    public BareVXLanIface(IPPort udpSockAddress) {
        super(udpSockAddress);
        this.udpSockAddress = udpSockAddress;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BareVXLanIface that = (BareVXLanIface) o;
        return Objects.equals(udpSockAddress, that.udpSockAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(udpSockAddress);
    }

    @Override
    public String name() {
        return udpSockAddress.formatToIPPortString();
    }

    @Override
    public void sendPacket(PacketBuffer pkb) {
        super.sendPacket(pkb);
    }

    @Override
    protected void manipulate() {
        // keep reserved fields empty
        sndBuf.put(1, (byte) 0);
        sndBuf.put(2, (byte) 0);
        sndBuf.put(3, (byte) 0);
        sndBuf.put(7, (byte) 0);
    }

    @Override
    public int getLocalSideVrf(int hintVrf) {
        return localSideVrf;
    }

    @Override
    public int getOverhead() {
        return 14 /* inner ethernet */ + 8 /* vxlan header */ + 8 /* udp header */ + 40 /* ipv6 header common */;
    }

    @Override
    public void setLocalSideVrf(int vrf) {
        this.localSideVrf = vrf;
    }
}
