package io.vproxy.vswitch.iface;

import io.vproxy.base.util.Consts;
import io.vproxy.vfd.IPPort;
import io.vproxy.vswitch.PacketBuffer;

import java.util.Objects;

public class RemoteSwitchIface extends AbstractBaseSwitchSocketIface {
    public final String alias;
    public final IPPort udpSockAddress;
    public final boolean addSwitchFlag;

    public RemoteSwitchIface(String alias, IPPort udpSockAddress, boolean addSwitchFlag) {
        super(udpSockAddress);
        this.alias = alias;
        this.udpSockAddress = udpSockAddress;
        this.addSwitchFlag = addSwitchFlag;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RemoteSwitchIface that = (RemoteSwitchIface) o;
        return Objects.equals(alias, that.alias) &&
            Objects.equals(udpSockAddress, that.udpSockAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(alias, udpSockAddress);
    }

    @Override
    public String name() {
        return "remote:" + alias;
    }

    @Override
    protected String toStringExtra() {
        return "," + udpSockAddress.formatToIPPortString();
    }

    @Override
    public void sendPacket(PacketBuffer pkb) {
        super.sendPacket(pkb);
    }

    @Override
    protected void manipulate() {
        if (addSwitchFlag) {
            sndBuf.put(1, (byte) (sndBuf.get(1) | ((Consts.I_AM_FROM_SWITCH >> 16) & 0xff)));
        } else {
            // remove all possible flags or counters
            sndBuf.put(1, (byte) 0);
            sndBuf.put(2, (byte) 0);
            sndBuf.put(3, (byte) 0);
            sndBuf.put(7, (byte) 0);
        }
    }

    @Override
    public int getLocalSideVrf(int hint) {
        return hint;
    }

    @Override
    public int getOverhead() {
        return 14 /* inner ethernet */ + 8 /* vxlan header */ + 8 /* udp header */ + 40 /* ipv6 header common */;
    }
}
