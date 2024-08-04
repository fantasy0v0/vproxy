package io.vproxy.vswitch.iface;

public class IfaceStatistics {
    private long rxPkts;
    private long txPkts;
    private long rxBytes;
    private long txBytes;
    private long rxErr;
    private long txErr;

    private long txCsumSkip;

    public void incrRxPkts() {
        incrRxPkts(1);
    }

    public void incrRxPkts(long rxPkts) {
        this.rxPkts += rxPkts;
    }

    public void incrTxPkts() {
        incrTxPkts(1);
    }

    public void incrTxPkts(long txPkts) {
        this.txPkts += txPkts;
    }

    public void incrRxBytes(long rxBytes) {
        this.rxBytes += rxBytes;
    }

    public void incrTxBytes(long txBytes) {
        this.txBytes += txBytes;
    }

    public void incrRxErr() {
        incrRxErr(1);
    }

    public void incrRxErr(long rxErr) {
        this.rxErr += rxErr;
    }

    public void incrTxErr() {
        incrTxErr(1);
    }

    public void incrTxErr(long txErr) {
        this.txErr += txErr;
    }

    public void incrCsumSkip() {
        incrCsumSkip(1);
    }

    public void incrCsumSkip(long csumSkip) {
        this.txCsumSkip += csumSkip;
    }

    public long getRxPkts() {
        return rxPkts;
    }

    public long getTxPkts() {
        return txPkts;
    }

    public long getRxBytes() {
        return rxBytes;
    }

    public long getTxBytes() {
        return txBytes;
    }

    public long getRxErr() {
        return rxErr;
    }

    public long getTxErr() {
        return txErr;
    }

    public long getTxCsumSkip() {
        return txCsumSkip;
    }

    @Override
    public String toString() {
        return "rx_pkts=" + rxPkts +
               " tx_pkts=" + txPkts +
               " rx_bytes=" + rxBytes +
               " tx_bytes=" + txBytes +
               " rx_err=" + rxErr +
               " tx_err=" + txErr +
               " csum_skip=" + txCsumSkip;
    }
}
