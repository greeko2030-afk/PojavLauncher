package com.supersonic.ssinternet.core;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

/** Small encoders that exist on every Android API level (java.util.Base64 needs API 26). */
public final class Codec {
    private static final char[] B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Codec() {}

    /** RFC 4648 base32 without padding. */
    public static String base32(byte[] data) {
        StringBuilder sb = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(B32[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
            buffer &= (1 << bits) - 1;
        }
        if (bits > 0) sb.append(B32[(buffer << (5 - bits)) & 31]);
        return sb.toString();
    }

    public static boolean isBase32(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'))) return false;
        }
        return true;
    }

    public static String hex(byte[] d) {
        char[] out = new char[d.length * 2];
        for (int i = 0; i < d.length; i++) {
            out[i * 2] = HEX[(d[i] >> 4) & 15];
            out[i * 2 + 1] = HEX[d[i] & 15];
        }
        return new String(out);
    }

    public static String urlEncode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (UnsupportedEncodingException | IllegalArgumentException e) {
            return "";
        }
    }
}
