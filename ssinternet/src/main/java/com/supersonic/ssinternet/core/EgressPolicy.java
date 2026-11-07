package com.supersonic.ssinternet.core;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * What a client may reach THROUGH the provider. The provider's own network (localhost, home LAN,
 * router, other devices, cloud metadata) must never be reachable, otherwise a client could attack it.
 * Names are resolved here, then only public addresses are used, and the socket connects to the exact
 * address that was checked (so DNS rebinding can not swap it afterwards).
 */
public final class EgressPolicy {
    public static final class Denied extends IOException {
        public Denied(String m) { super(m); }
    }

    private final Set<Integer> blockedPorts = new HashSet<>();
    private volatile boolean allowPrivate = false; // for tests only

    public EgressPolicy() {
        blockedPorts.add(25); // outgoing SMTP: the classic abuse channel; mail clients use 465/587
    }

    public EgressPolicy blockPort(int p) { blockedPorts.add(p); return this; }

    /** Tests only. Never expose in the UI. */
    public EgressPolicy allowPrivateForTests(boolean v) { allowPrivate = v; return this; }

    public Socket connect(String host, int port, int timeoutMs) throws IOException {
        if (port < 1 || port > 65535) throw new Denied("bad port");
        if (blockedPorts.contains(port)) throw new Denied("port " + port + " is blocked by the provider");
        InetAddress[] all;
        try {
            all = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new UnknownHostException(host);
        }
        List<InetAddress> usable = new ArrayList<>();
        for (InetAddress a : all) if (allowPrivate || isPublic(a)) usable.add(a);
        if (usable.isEmpty()) throw new Denied("destination is not a public internet address");
        IOException last = null;
        int tries = 0;
        for (InetAddress a : usable) {
            if (tries++ >= 3) break;
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress(a, port), timeoutMs);
                s.setTcpNoDelay(true);
                return s;
            } catch (IOException e) {
                last = e;
                try { s.close(); } catch (IOException ignored) {}
            }
        }
        throw last != null ? last : new IOException("connect failed");
    }

    public static boolean isPublic(InetAddress a) {
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) return isPublic4(b);
        if (a instanceof Inet6Address) {
            if (b.length != 16) return false;
            // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::/96) carry an IPv4 address
            boolean zeros10 = true;
            for (int i = 0; i < 10; i++) if (b[i] != 0) zeros10 = false;
            if (zeros10 && (b[10] & 0xff) == 0xff && (b[11] & 0xff) == 0xff) return isPublic4(new byte[]{b[12], b[13], b[14], b[15]});
            boolean zeros12 = true;
            for (int i = 0; i < 12; i++) if (b[i] != 0) zeros12 = false;
            if (zeros12) return false; // ::, ::1, ::a.b.c.d
            if ((b[0] & 0xff) == 0x00 && (b[1] & 0xff) == 0x64 && (b[2] & 0xff) == 0xff && (b[3] & 0xff) == 0x9b) {
                boolean z = true;
                for (int i = 4; i < 12; i++) if (b[i] != 0) z = false;
                if (z) return isPublic4(new byte[]{b[12], b[13], b[14], b[15]});
            }
            int b0 = b[0] & 0xff, b1 = b[1] & 0xff;
            if ((b0 & 0xfe) == 0xfc) return false;                 // fc00::/7 unique local
            if (b0 == 0xfe && (b1 & 0xc0) == 0x80) return false;   // fe80::/10 link local
            if (b0 == 0xfe && (b1 & 0xc0) == 0xc0) return false;   // fec0::/10 site local
            if (b0 == 0xff) return false;                          // multicast
            if (b0 == 0x20 && b1 == 0x01 && b[2] == 0x0d && (b[3] & 0xff) == 0xb8) return false; // documentation
            return true;
        }
        return false;
    }

    private static boolean isPublic4(byte[] b) {
        int b0 = b[0] & 0xff, b1 = b[1] & 0xff, b2 = b[2] & 0xff;
        if (b0 == 0 || b0 == 10 || b0 == 127) return false;
        if (b0 >= 224) return false;                              // multicast + reserved + broadcast
        if (b0 == 100 && (b1 & 0xc0) == 64) return false;        // 100.64/10 carrier NAT (also many VPN/tailnets)
        if (b0 == 169 && b1 == 254) return false;                // link local, cloud metadata 169.254.169.254
        if (b0 == 172 && (b1 & 0xf0) == 16) return false;        // 172.16/12
        if (b0 == 192 && b1 == 168) return false;                // 192.168/16
        if (b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2)) return false; // 192.0.0/24, 192.0.2/24
        if (b0 == 198 && (b1 & 0xfe) == 18) return false;        // 198.18/15 benchmarking
        if (b0 == 198 && b1 == 51 && b2 == 100) return false;    // 198.51.100/24
        if (b0 == 203 && b1 == 0 && b2 == 113) return false;     // 203.0.113/24
        return true;
    }
}
