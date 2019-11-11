package vproxy.util.bytearray;

import vproxy.util.ByteArray;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public abstract class AbstractByteArray implements ByteArray {
    protected void checkBoundForOffset(int off) {
        if (off < 0) {
            throw new IllegalArgumentException("off=" + off + " < 0");
        }
        if (off >= length()) {
            throw new ArrayIndexOutOfBoundsException("off=" + off + ", length=" + length());
        }
    }

    protected void checkBoundForOffsetAndLength(int off, int len) {
        checkBoundForOffset(off);
        if (len < 0) {
            throw new IllegalArgumentException("len=" + len + " < 0");
        }
        if (off > length() || off + len > length()) {
            throw new ArrayIndexOutOfBoundsException("off=" + off + ", len=" + len + ", length=" + length());
        }
    }

    protected void checkBoundForByteBufferAndOffsetAndLength(ByteBuffer byteBuffer, int off, int len) {
        checkBoundForOffsetAndLength(off, len);

        int bLen = byteBuffer.limit() - byteBuffer.position();
        if (bLen < len) {
            throw new IndexOutOfBoundsException("byteBuffer.length=" + bLen + ", len=" + len);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ByteArray))
            return false;
        ByteArray o = (ByteArray) obj;

        final int len = this.length();

        if (len != o.length())
            return false;

        for (int i = 0; i < len; ++i) {
            if (this.get(i) != o.get(i))
                return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        final int len = length();
        int ret = 0;
        for (int i = 0; i < len; ++i) {
            ret = (ret << 31) | get(i);
        }
        return ret;
    }

    @Override
    public String toString() {
        return new String(toJavaArray(), StandardCharsets.UTF_8);
    }
}
