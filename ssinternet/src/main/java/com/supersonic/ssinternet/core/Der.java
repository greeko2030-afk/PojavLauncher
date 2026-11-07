package com.supersonic.ssinternet.core;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/** Minimal DER writer, just enough to build a self-signed X.509 certificate without BouncyCastle. */
final class Der {
    private Der() {}

    static byte[] tlv(int tag, byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) len += p.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream(len + 6);
        out.write(tag);
        if (len < 128) {
            out.write(len);
        } else if (len < 256) {
            out.write(0x81);
            out.write(len);
        } else if (len < 65536) {
            out.write(0x82);
            out.write(len >> 8);
            out.write(len);
        } else {
            out.write(0x83);
            out.write(len >> 16);
            out.write(len >> 8);
            out.write(len);
        }
        for (byte[] p : parts) out.write(p, 0, p.length);
        return out.toByteArray();
    }

    static byte[] seq(byte[]... p) { return tlv(0x30, p); }

    static byte[] set(byte[]... p) { return tlv(0x31, p); }

    static byte[] integer(BigInteger v) { return tlv(0x02, v.toByteArray()); }

    static byte[] utf8(String s) { return tlv(0x0C, s.getBytes(java.nio.charset.Charset.forName("UTF-8"))); }

    static byte[] bitString(byte[] content) {
        byte[] b = new byte[content.length + 1];
        System.arraycopy(content, 0, b, 1, content.length);
        return tlv(0x03, b);
    }

    static byte[] oid(String dotted) {
        String[] parts = dotted.split("\\.");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]));
        for (int i = 2; i < parts.length; i++) {
            long v = Long.parseLong(parts[i]);
            byte[] tmp = new byte[10];
            int n = 0;
            tmp[n++] = (byte) (v & 0x7f);
            v >>= 7;
            while (v > 0) {
                tmp[n++] = (byte) ((v & 0x7f) | 0x80);
                v >>= 7;
            }
            while (n > 0) out.write(tmp[--n]);
        }
        return tlv(0x06, out.toByteArray());
    }

    /** UTCTime, valid for years 1950-2049. */
    static byte[] utcTime(Date d) {
        SimpleDateFormat f = new SimpleDateFormat("yyMMddHHmmss'Z'");
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return tlv(0x17, f.format(d).getBytes(java.nio.charset.Charset.forName("US-ASCII")));
    }
}
