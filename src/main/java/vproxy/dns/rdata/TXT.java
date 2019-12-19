package vproxy.dns.rdata;

import vproxy.dns.DNSType;
import vproxy.dns.Formatter;
import vproxy.dns.InvalidDNSPacketException;
import vproxy.util.ByteArray;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class TXT implements RData {
    public List<String> texts = new ArrayList<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TXT txt = (TXT) o;
        return Objects.equals(texts, txt.texts);
    }

    @Override
    public int hashCode() {
        return Objects.hash(texts);
    }

    @Override
    public String toString() {
        return "TXT{" +
            "texts=" + texts +
            '}';
    }

    @Override
    public ByteArray toByteArray() {
        if (texts.isEmpty()) {
            return ByteArray.from(new byte[0]);
        }
        ByteArray ret = Formatter.formatString(texts.get(0));
        for (int i = 1; i < texts.size(); ++i) {
            ret = ret.concat(Formatter.formatString(texts.get(i)));
        }
        return ret;
    }

    @Override
    public DNSType type() {
        return DNSType.TXT;
    }

    @Override
    public void fromByteArray(ByteArray data) throws InvalidDNSPacketException {
        int offset = 0;
        List<String> tmp = new LinkedList<>();
        while (offset < data.length()) {
            int len = data.uint8(offset);
            ++offset;
            if (data.length() - offset < len) {
                throw new InvalidDNSPacketException("require more bytes in txt rdata field");
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; ++i) {
                char c = (char) data.get(offset++);
                sb.append(c);
            }
            String s = sb.toString();
            tmp.add(s);
        }
        assert offset == data.length();
        texts.addAll(tmp);
    }
}
