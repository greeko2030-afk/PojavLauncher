package com.supersonic.ssinternet.relay;

import com.supersonic.ssinternet.core.Codec;
import com.supersonic.ssinternet.core.Identity;
import com.supersonic.ssinternet.core.LineIO;
import com.supersonic.ssinternet.core.TlsUtil;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * Rendezvous + byte relay. Providers (behind mobile NAT, no public IP) keep ONE outbound connection to it.
 * A client asks for a provider; the relay tells the provider, the provider dials back a second outbound
 * connection, and the relay joins the two sockets. What flows through is a second TLS session between
 * client and provider, so the relay moves bytes it can not read or change undetected.
 */
public final class RelayServer implements Closeable {
    private static final SecureRandom RNG = new SecureRandom();

    public static final class Limits {
        public int maxConnectionsPerIp = 256;
        public int maxSessionsPerDevice = 16;
        public int maxProviders = 20000;
        public int connectTimeoutSeconds = 20;
        public int spliceIdleSeconds = 120;
    }

    private static final class ProviderConn {
        final String id;
        final SSLSocket sock;
        final OutputStream out;
        volatile String name = "";
        volatile String country = "";
        volatile boolean listed;
        volatile int max = 5;
        volatile long lastSeen = System.currentTimeMillis();
        final AtomicInteger active = new AtomicInteger();

        ProviderConn(String id, SSLSocket sock) throws IOException {
            this.id = id;
            this.sock = sock;
            this.out = sock.getOutputStream();
        }

        void send(String line) throws IOException {
            synchronized (out) { LineIO.writeLine(out, line); }
        }

        void close() { try { sock.close(); } catch (IOException ignored) {} }
    }

    private static final class Pending {
        final String providerId;
        final CountDownLatch latch = new CountDownLatch(1);
        volatile SSLSocket providerSock;
        Pending(String providerId) { this.providerId = providerId; }
    }

    private final SSLServerSocket server;
    private final Limits limits;
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "ss-relay");
        t.setDaemon(true);
        return t;
    });
    private final ScheduledExecutorService pinger = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ss-relay-ping");
        t.setDaemon(true);
        return t;
    });
    private final ConcurrentHashMap<String, ProviderConn> providers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Pending> pending = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> perIp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> perDevice = new ConcurrentHashMap<>();
    private volatile boolean closed;
    public final AtomicLong sessionsTotal = new AtomicLong();
    public final AtomicLong bytesRelayed = new AtomicLong();

    public RelayServer(SSLContext ctx, int port, Limits limits) throws IOException {
        this.limits = limits;
        this.server = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port, 256);
        this.server.setWantClientAuth(true);
        Thread t = new Thread(this::acceptLoop, "ss-relay-accept");
        t.setDaemon(true);
        t.start();
        pinger.scheduleWithFixedDelay(this::pingAll, 25, 25, TimeUnit.SECONDS);
    }

    public int getPort() { return server.getLocalPort(); }

    public int providerCount() { return providers.size(); }

    private void log(String s) { System.out.println("[relay] " + s); }

    private static String shortId(String id) { return id.substring(0, 8); }

    private void acceptLoop() {
        while (!closed) {
            try {
                final SSLSocket s = (SSLSocket) server.accept();
                pool.execute(() -> handle(s));
            } catch (IOException e) {
                if (closed) return;
            }
        }
    }

    private void pingAll() {
        long now = System.currentTimeMillis();
        for (ProviderConn p : providers.values()) {
            if (now - p.lastSeen > 80_000) {
                p.close();
                continue;
            }
            try { p.send("PING"); } catch (IOException e) { p.close(); }
        }
    }

    private static boolean acquire(ConcurrentHashMap<String, AtomicInteger> m, String key, int max) {
        AtomicInteger c = m.computeIfAbsent(key, k -> new AtomicInteger());
        if (c.incrementAndGet() > max) {
            c.decrementAndGet();
            return false;
        }
        return true;
    }

    private static void release(ConcurrentHashMap<String, AtomicInteger> m, String key) {
        AtomicInteger c = m.get(key);
        if (c != null && c.decrementAndGet() <= 0) m.remove(key, c);
    }

    private void handle(SSLSocket s) {
        String ip = s.getInetAddress().getHostAddress();
        if (!acquire(perIp, ip, limits.maxConnectionsPerIp)) {
            try { s.close(); } catch (IOException ignored) {}
            return;
        }
        boolean keepOpen = false;
        try {
            s.setSoTimeout(15_000);
            s.setTcpNoDelay(true);
            s.startHandshake();
            String dev;
            try {
                dev = TlsUtil.peerId(s);
            } catch (IOException e) {
                return; // no client certificate: no service
            }
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            String[] hello = LineIO.readLine(in, 256).split(" ");
            if (hello.length < 3 || !hello[0].equals("HELLO") || !hello[2].equals("1")) {
                LineIO.writeLine(out, "ERR PROTOCOL");
                return;
            }
            switch (hello[1]) {
                case "PROVIDER":
                    LineIO.writeLine(out, "OK " + dev);
                    providerLoop(s, dev);
                    break;
                case "CLIENT":
                    LineIO.writeLine(out, "OK " + dev);
                    clientLoop(s, dev);
                    break;
                case "ACCEPT":
                    if (hello.length != 4) {
                        LineIO.writeLine(out, "ERR PROTOCOL");
                        return;
                    }
                    keepOpen = acceptSession(s, dev, hello[3]);
                    break;
                default:
                    LineIO.writeLine(out, "ERR PROTOCOL");
            }
        } catch (IOException | RuntimeException e) {
            // connection problems are normal on the internet
        } finally {
            release(perIp, ip);
            if (!keepOpen) try { s.close(); } catch (IOException ignored) {}
        }
    }

    // ------------------------------------------------------------------ providers

    private void providerLoop(SSLSocket s, String dev) throws IOException {
        InputStream in = s.getInputStream();
        String reg = LineIO.readLine(in, 512);
        if (!reg.startsWith("REGISTER")) throw new IOException("expected REGISTER");
        if (providers.size() >= limits.maxProviders && !providers.containsKey(dev)) {
            LineIO.writeLine(s.getOutputStream(), "ERR FULL");
            return;
        }
        ProviderConn pc = new ProviderConn(dev, s);
        applyListing(pc, reg);
        ProviderConn old = providers.put(dev, pc);
        if (old != null) old.close();
        pc.send("OK");
        s.setSoTimeout(0);
        log("provider online " + shortId(dev) + " listed=" + pc.listed);
        try {
            while (!closed) {
                String line = LineIO.readLine(in, 512);
                pc.lastSeen = System.currentTimeMillis();
                if (line.equals("PONG")) continue;
                if (line.startsWith("UPDATE")) applyListing(pc, line);
                else if (line.equals("BYE")) break;
            }
        } finally {
            providers.remove(dev, pc);
            pc.close();
            log("provider offline " + shortId(dev));
        }
    }

    private static void applyListing(ProviderConn pc, String line) {
        for (String tok : line.split(" ")) {
            int eq = tok.indexOf('=');
            if (eq < 1) continue;
            String k = tok.substring(0, eq), v = tok.substring(eq + 1);
            switch (k) {
                case "name": {
                    String n = Codec.urlDecode(v).replaceAll("\\p{Cntrl}", "").trim();
                    pc.name = n.length() > 40 ? n.substring(0, 40) : n;
                    break;
                }
                case "country": pc.country = v.matches("[A-Za-z]{2}") ? v.toUpperCase(java.util.Locale.US) : ""; break;
                case "listed": pc.listed = v.equals("1"); break;
                case "max":
                    try { pc.max = Math.max(1, Math.min(100, Integer.parseInt(v))); } catch (NumberFormatException ignored) {}
                    break;
                default:
            }
        }
    }

    /** The provider's data connection. The client's handler thread takes over from here. */
    private boolean acceptSession(SSLSocket s, String dev, String sid) {
        Pending p = pending.get(sid);
        if (p == null || !p.providerId.equals(dev) || p.providerSock != null) return false;
        synchronized (p) {
            if (p.providerSock != null) return false;
            p.providerSock = s;
        }
        p.latch.countDown();
        return true;
    }

    // ------------------------------------------------------------------ clients

    private void clientLoop(SSLSocket s, String dev) throws IOException {
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        s.setSoTimeout(60_000);
        while (!closed) {
            String line = LineIO.readLine(in, 256);
            if (line.equals("BYE")) return;
            if (line.equals("LIST")) {
                List<ProviderConn> all = new ArrayList<>();
                for (ProviderConn p : providers.values()) if (p.listed) all.add(p);
                Collections.sort(all, new Comparator<ProviderConn>() {
                    @Override public int compare(ProviderConn a, ProviderConn b) { return Integer.compare(a.active.get(), b.active.get()); }
                });
                StringBuilder sb = new StringBuilder();
                int n = 0;
                for (ProviderConn p : all) {
                    if (n++ >= 200) break;
                    sb.append("PROVIDER ").append(p.id).append(' ').append(Codec.urlEncode(p.name)).append(' ')
                            .append(p.country.isEmpty() ? "-" : p.country).append(' ')
                            .append(p.active.get()).append(' ').append(p.max).append('\n');
                }
                sb.append("END");
                LineIO.writeLine(out, sb.toString());
            } else if (line.startsWith("CONNECT ")) {
                if (connect(s, dev, line.substring(8).trim())) return;
            } else {
                LineIO.writeLine(out, "ERR PROTOCOL");
            }
        }
    }

    /** @return true if the connection was used for a session (and is now finished). */
    private boolean connect(SSLSocket client, String dev, String providerId) throws IOException {
        OutputStream cout = client.getOutputStream();
        if (!Identity.isValidId(providerId)) {
            LineIO.writeLine(cout, "ERR BADID");
            return false;
        }
        ProviderConn p = providers.get(Identity.normalizeId(providerId));
        if (p == null) {
            LineIO.writeLine(cout, "ERR OFFLINE");
            return false;
        }
        if (!acquire(perDevice, dev, limits.maxSessionsPerDevice)) {
            LineIO.writeLine(cout, "ERR LIMIT");
            return false;
        }
        boolean slot = false;
        String sid = null;
        SSLSocket ps = null;
        try {
            if (p.active.incrementAndGet() > p.max) {
                p.active.decrementAndGet();
                LineIO.writeLine(cout, "ERR BUSY");
                return false;
            }
            slot = true;
            byte[] r = new byte[16];
            RNG.nextBytes(r);
            sid = Codec.hex(r);
            Pending pend = new Pending(p.id);
            pending.put(sid, pend);
            try {
                p.send("INCOMING " + sid + " " + dev);
            } catch (IOException e) {
                LineIO.writeLine(cout, "ERR OFFLINE");
                return false;
            }
            boolean ok;
            try {
                ok = pend.latch.await(limits.connectTimeoutSeconds, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
            pending.remove(sid);
            ps = pend.providerSock;
            if (!ok || ps == null) {
                LineIO.writeLine(cout, "ERR TIMEOUT");
                return false;
            }
            LineIO.writeLine(ps.getOutputStream(), "OK");
            LineIO.writeLine(cout, "OK");
            sessionsTotal.incrementAndGet();
            log("session " + shortId(dev) + " -> " + shortId(p.id));
            splice(client, ps);
            return true;
        } finally {
            if (sid != null) pending.remove(sid);
            if (slot) p.active.decrementAndGet();
            release(perDevice, dev);
            if (ps != null) try { ps.close(); } catch (IOException ignored) {}
        }
    }

    private void splice(final SSLSocket a, final SSLSocket b) {
        try {
            a.setSoTimeout(limits.spliceIdleSeconds * 1000);
            b.setSoTimeout(limits.spliceIdleSeconds * 1000);
            a.setTcpNoDelay(true);
            b.setTcpNoDelay(true);
        } catch (IOException e) {
            return;
        }
        Thread t = new Thread(() -> pump(a, b), "ss-relay-splice");
        t.setDaemon(true);
        t.start();
        pump(b, a);
        try { t.join(5000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private void pump(Socket from, Socket to) {
        byte[] buf = new byte[16384];
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            int n;
            while ((n = in.read(buf)) >= 0) {
                out.write(buf, 0, n);
                out.flush();
                bytesRelayed.addAndGet(n);
            }
        } catch (IOException ignored) {
        } finally {
            try { from.close(); } catch (IOException ignored) {}
            try { to.close(); } catch (IOException ignored) {}
        }
    }

    @Override public void close() {
        closed = true;
        pinger.shutdownNow();
        try { server.close(); } catch (IOException ignored) {}
        for (ProviderConn p : providers.values()) p.close();
        pool.shutdownNow();
    }
}
