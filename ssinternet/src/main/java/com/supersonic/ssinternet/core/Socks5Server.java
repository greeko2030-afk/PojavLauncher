package com.supersonic.ssinternet.core;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.concurrent.Executor;

/**
 * Local SOCKS5 proxy (CONNECT only) on 127.0.0.1. Host names are handed to the provider unresolved,
 * so DNS lookups happen at the provider too and do not leak to the local network.
 */
public final class Socks5Server implements Closeable {
    public interface Connector {
        MuxStream open(String host, int port) throws IOException;
    }

    private final ServerSocket server;
    private final Connector connector;
    private final Executor pool;
    private volatile boolean closed;

    public Socks5Server(int port, Connector connector, Executor pool) throws IOException {
        this.server = new ServerSocket();
        this.server.setReuseAddress(true);
        this.server.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), port), 64);
        this.connector = connector;
        this.pool = pool;
        Thread t = new Thread(this::acceptLoop, "ss-socks-accept");
        t.setDaemon(true);
        t.start();
    }

    public int getPort() { return server.getLocalPort(); }

    private void acceptLoop() {
        while (!closed) {
            try {
                final Socket c = server.accept();
                pool.execute(() -> handle(c));
            } catch (IOException e) {
                if (closed) return;
            }
        }
    }

    private void handle(Socket c) {
        try {
            c.setTcpNoDelay(true);
            c.setSoTimeout(15_000);
            DataInputStream in = new DataInputStream(c.getInputStream());
            OutputStream out = c.getOutputStream();
            int first = in.readUnsignedByte();
            if (first != 5) {
                handleHttp(c, in, out, first); // not SOCKS: an HTTP proxy request (browsers, Android Wi-Fi proxy setting)
                return;
            }
            int nm = in.readUnsignedByte();
            boolean noAuth = false;
            for (int i = 0; i < nm; i++) if (in.readUnsignedByte() == 0) noAuth = true;
            if (!noAuth) {
                out.write(new byte[]{5, (byte) 0xff});
                out.flush();
                c.close();
                return;
            }
            out.write(new byte[]{5, 0});
            out.flush();
            if (in.readUnsignedByte() != 5) throw new IOException("bad request");
            int cmd = in.readUnsignedByte();
            in.readUnsignedByte();
            int atyp = in.readUnsignedByte();
            String host;
            if (atyp == 1) {
                byte[] a = new byte[4];
                in.readFully(a);
                host = InetAddress.getByAddress(a).getHostAddress();
            } else if (atyp == 3) {
                int l = in.readUnsignedByte();
                byte[] a = new byte[l];
                in.readFully(a);
                host = new String(a, Charset.forName("UTF-8"));
            } else if (atyp == 4) {
                byte[] a = new byte[16];
                in.readFully(a);
                host = InetAddress.getByAddress(a).getHostAddress();
            } else {
                reply(out, 8);
                c.close();
                return;
            }
            int port = in.readUnsignedShort();
            if (cmd != 1) {
                reply(out, 7);
                c.close();
                return;
            }
            MuxStream st;
            try {
                st = connector.open(host, port);
            } catch (MuxSession.OpenRefused r) {
                reply(out, mapCode(r.code));
                c.close();
                return;
            } catch (IOException e) {
                reply(out, 1);
                c.close();
                return;
            }
            reply(out, 0);
            c.setSoTimeout(0);
            Pipes.bridge(c, st, Pipes.OPEN, pool);
        } catch (IOException e) {
            try { c.close(); } catch (IOException ignored) {}
        }
    }

    // ------------------------------------------------------------------ HTTP proxy (CONNECT for https, absolute-URI for http)

    private void handleHttp(Socket c, DataInputStream in, OutputStream out, int first) throws IOException {
        java.io.ByteArrayOutputStream head = new java.io.ByteArrayOutputStream();
        head.write(first);
        int last4 = first;
        while (last4 != 0x0D0A0D0A) {
            int b = in.readUnsignedByte();
            head.write(b);
            if (head.size() > 16384) throw new IOException("request header too large");
            last4 = (last4 << 8) | b;
        }
        String[] lines = new String(head.toByteArray(), Charset.forName("ISO-8859-1")).split("\r\n");
        String[] rl = lines[0].split(" ");
        if (rl.length != 3) { httpError(out, "400 Bad Request"); c.close(); return; }
        String method = rl[0], target = rl[1], version = rl[2];
        boolean connect = method.equalsIgnoreCase("CONNECT");
        String hostPort, path = "/";
        int defPort;
        if (connect) {
            hostPort = target;
            defPort = 443;
        } else if (target.regionMatches(true, 0, "http://", 0, 7)) {
            String rest = target.substring(7);
            int slash = rest.indexOf('/');
            hostPort = slash < 0 ? rest : rest.substring(0, slash);
            path = slash < 0 ? "/" : rest.substring(slash);
            defPort = 80;
        } else {
            httpError(out, "400 Bad Request");
            c.close();
            return;
        }
        String host;
        int port = defPort;
        try {
            if (hostPort.startsWith("[")) { // IPv6 literal
                int e = hostPort.indexOf(']');
                host = hostPort.substring(1, e);
                if (hostPort.length() > e + 2 && hostPort.charAt(e + 1) == ':') port = Integer.parseInt(hostPort.substring(e + 2));
            } else {
                int i = hostPort.lastIndexOf(':');
                if (i >= 0) { host = hostPort.substring(0, i); port = Integer.parseInt(hostPort.substring(i + 1)); }
                else host = hostPort;
            }
        } catch (RuntimeException e) {
            httpError(out, "400 Bad Request");
            c.close();
            return;
        }
        MuxStream st;
        try {
            st = connector.open(host, port);
        } catch (MuxSession.OpenRefused r) {
            httpError(out, r.code == MuxSession.ERR_DENIED || r.code == MuxSession.ERR_CAP ? "403 Forbidden" : "502 Bad Gateway");
            c.close();
            return;
        } catch (IOException e) {
            httpError(out, "502 Bad Gateway");
            c.close();
            return;
        }
        if (connect) {
            out.write("HTTP/1.1 200 Connection established\r\n\r\n".getBytes(Charset.forName("US-ASCII")));
            out.flush();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(method).append(' ').append(path).append(' ').append(version).append("\r\n");
            for (int i = 1; i < lines.length; i++) {
                String l = lines[i];
                String lower = l.toLowerCase(java.util.Locale.US);
                if (l.isEmpty() || lower.startsWith("proxy-") || lower.startsWith("connection:") || lower.startsWith("keep-alive:")) continue;
                sb.append(l).append("\r\n");
            }
            sb.append("Connection: close\r\n\r\n");
            st.getOutputStream().write(sb.toString().getBytes(Charset.forName("ISO-8859-1")));
        }
        c.setSoTimeout(0);
        Pipes.bridge(c, st, Pipes.OPEN, pool);
    }

    private static void httpError(OutputStream out, String status) throws IOException {
        out.write(("HTTP/1.1 " + status + "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").getBytes(Charset.forName("US-ASCII")));
        out.flush();
    }

    private static int mapCode(int code) {
        switch (code) {
            case MuxSession.ERR_DENIED:
            case MuxSession.ERR_CAP: return 2;
            case MuxSession.ERR_UNREACHABLE: return 4;
            case MuxSession.ERR_REFUSED: return 5;
            case MuxSession.ERR_TIMEOUT: return 6;
            default: return 1;
        }
    }

    private static void reply(OutputStream out, int code) throws IOException {
        out.write(new byte[]{5, (byte) code, 0, 1, 0, 0, 0, 0, 0, 0});
        out.flush();
    }

    @Override public void close() {
        closed = true;
        try { server.close(); } catch (IOException ignored) {}
    }
}
