package com.supersonic.ssinternet.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;

/**
 * Line reading WITHOUT read-ahead. The relay protocol switches from text lines to raw (TLS) bytes
 * in the middle of a connection, so a buffered reader would swallow bytes that belong to the next layer.
 */
public final class LineIO {
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private LineIO() {}

    public static String readLine(InputStream in, int max) throws IOException {
        byte[] buf = new byte[64];
        int n = 0;
        while (true) {
            int b = in.read();
            if (b < 0) {
                if (n == 0) throw new IOException("connection closed");
                break;
            }
            if (b == '\n') break;
            if (b != '\r') {
                if (n >= max) throw new IOException("line too long");
                if (n == buf.length) buf = java.util.Arrays.copyOf(buf, Math.min(max, n * 2));
                buf[n++] = (byte) b;
            }
        }
        return new String(buf, 0, n, UTF8);
    }

    public static void writeLine(OutputStream out, String line) throws IOException {
        out.write((line + "\n").getBytes(UTF8));
        out.flush();
    }
}
