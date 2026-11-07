package com.supersonic.ssinternet.core;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

/**
 * Client mode: connects to one provider (through the relay, end-to-end encrypted) and offers a local
 * SOCKS5 proxy. Whatever is pointed at that proxy leaves to the internet from the provider's connection.
 */
public final class ClientEngine {
    public enum State { IDLE, CONNECTING, WAITING_APPROVAL, CONNECTED, DENIED, ERROR }

    private final Identity identity;
    private final RelayLink link;
    private final String providerId;
    private final int socksPortWanted;
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "ss-client");
        t.setDaemon(true);
        return t;
    });
    private final ScheduledExecutorService ticker = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ss-client-tick");
        t.setDaemon(true);
        return t;
    });
    private volatile State state = State.IDLE;
    private volatile String detail = "";
    private volatile boolean running;
    private volatile MuxSession mux;
    private volatile SSLSocket control;
    private Socks5Server socks;
    private Thread loop;
    private int tickCount;
    private volatile long sessionDown, sessionUp; // totals of earlier tunnels in this run

    public ClientEngine(Identity identity, String relayHost, int relayPort, String relayPin, String providerId, int socksPort)
            throws IOException, java.security.GeneralSecurityException {
        this.identity = identity;
        this.providerId = Identity.normalizeId(providerId);
        this.link = new RelayLink(relayHost, relayPort, relayPin, identity);
        this.socksPortWanted = socksPort;
    }

    public State state() { return state; }
    public String detail() { return detail; }
    public int socksPort() { return socks == null ? -1 : socks.getPort(); }
    public String providerId() { return providerId; }

    public long rttMillis() { MuxSession m = mux; return m == null ? -1 : m.rttMillis(); }
    public long downRate() { MuxSession m = mux; return m == null ? 0 : m.stats.rxRate(); }
    public long upRate() { MuxSession m = mux; return m == null ? 0 : m.stats.txRate(); }
    public long downBytes() { MuxSession m = mux; return sessionDown + (m == null ? 0 : m.stats.received.get()); }
    public long upBytes() { MuxSession m = mux; return sessionUp + (m == null ? 0 : m.stats.sent.get()); }
    /** Tunnel is up AND the provider answered within the last 12 s (any frame counts, so a busy tunnel is healthy). */
    public boolean isUsable() {
        MuxSession m = mux;
        return state == State.CONNECTED && m != null && !m.isClosed() && m.millisSinceLastRead() < 12_000;
    }

    /** Still trying for the first time, no verdict yet. */
    public boolean isConnecting() { return state == State.CONNECTING; }

    public int openConnections() { MuxSession m = mux; return m == null ? 0 : m.streamCount(); }

    public synchronized void start() throws IOException {
        if (running) return;
        running = true;
        sessionDown = sessionUp = 0;
        if (socks == null) {
            socks = new Socks5Server(socksPortWanted, (host, port) -> {
                MuxSession m = mux;
                // right after start the tunnel needs a moment: wait for it instead of failing the first requests
                for (int i = 0; (m == null || m.isClosed()) && state == State.CONNECTING && i < 100; i++) {
                    try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
                    m = mux;
                }
                if (m == null || m.isClosed()) throw new MuxSession.OpenRefused(MuxSession.ERR_UNREACHABLE, "SS Internet is not connected");
                return m.open(host, port, 20_000);
            }, pool);
        }
        ticker.scheduleWithFixedDelay(this::tick, 1, 1, TimeUnit.SECONDS);
        loop = new Thread(this::connectLoop, "ss-client-connect");
        loop.setDaemon(true);
        loop.start();
    }

    public synchronized void stop() {
        running = false;
        SSLSocket c = control;
        if (c != null) try { c.close(); } catch (IOException ignored) {}
        MuxSession m = mux;
        if (m != null) m.close("stopped");
        if (socks != null) {
            socks.close();
            socks = null;
        }
        state = State.IDLE;
        detail = "";
    }

    /** Real download throughput through the tunnel in bytes/s (provider to this device). */
    public double speedTest(int bytes) throws IOException {
        MuxSession m = mux;
        if (m == null || m.isClosed()) throw new IOException("not connected");
        return m.speedTest(bytes, 60_000);
    }

    private void tick() {
        MuxSession m = mux;
        if (m == null) return;
        m.stats.tick();
        if (m.millisSinceLastRead() > 15_000) m.close("no data from provider for 15 s");
        if ((++tickCount % 5) == 0) try { m.sendPing(); } catch (IOException ignored) {}
    }

    private void connectLoop() {
        long backoff = 2000;
        while (running) {
            try {
                state = State.CONNECTING;
                detail = "connecting via relay";
                boolean connected = connectOnce();
                if (!running) return;
                if (state == State.DENIED) return;
                if (connected) backoff = 2000;
            } catch (IOException | RuntimeException e) {
                if (!running) return;
                state = State.ERROR;
                detail = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            }
            long wait = state == State.WAITING_APPROVAL ? 5000 : backoff;
            try { Thread.sleep(wait); } catch (InterruptedException e) { return; }
            if (state != State.WAITING_APPROVAL) backoff = Math.min(backoff * 2, 30_000);
        }
    }

    /** @return true if a tunnel was established (and later ended). */
    private boolean connectOnce() throws IOException {
        SSLSocket outer = link.connect();
        control = outer;
        boolean handedOver = false;
        try {
            RelayLink.hello(outer, "CLIENT", null);
            InputStream in = outer.getInputStream();
            LineIO.writeLine(outer.getOutputStream(), "CONNECT " + providerId);
            String r = LineIO.readLine(in, 256);
            if (!r.equals("OK")) {
                String why = r.startsWith("ERR ") ? r.substring(4) : r;
                state = State.ERROR;
                detail = why.equals("OFFLINE") ? "provider is offline" : why.equals("BUSY") ? "provider is busy" : why.equals("TIMEOUT") ? "provider did not answer" : "relay: " + why;
                return false;
            }
            SSLContext ctx;
            try {
                ctx = TlsUtil.context(identity, new TrustManager[]{new TlsUtil.PinTrustManager(providerId)});
            } catch (java.security.GeneralSecurityException e) {
                throw new IOException("TLS setup failed", e);
            }
            SSLSocket inner = (SSLSocket) ctx.getSocketFactory().createSocket(outer, "ss-peer", outer.getPort(), true);
            TlsUtil.harden(inner);
            inner.setSoTimeout(30_000);
            try {
                inner.startHandshake();
            } catch (IOException e) {
                throw new IOException("could not verify the provider's identity (wrong ID or tampering): " + e.getMessage(), e);
            }
            String status = LineIO.readLine(inner.getInputStream(), 64);
            switch (status) {
                case "OK":
                    break;
                case "PENDING":
                    state = State.WAITING_APPROVAL;
                    detail = "waiting for the provider to approve this device";
                    return false;
                case "DENIED":
                    state = State.DENIED;
                    detail = "the provider blocked this device";
                    return false;
                case "BUSY":
                    state = State.ERROR;
                    detail = "provider has no free slot";
                    return false;
                case "FULL":
                    state = State.ERROR;
                    detail = "provider's data limit is reached";
                    return false;
                default:
                    throw new IOException("unexpected provider answer");
            }
            inner.setSoTimeout(0);
            final MuxSession m = new MuxSession(inner, true, null, pool);
            handedOver = true;
            final Object done = new Object();
            final boolean[] ended = new boolean[1];
            m.setCloseListener((s, reason) -> {
                sessionDown += s.stats.received.get();
                sessionUp += s.stats.sent.get();
                if (mux == s) {
                    state = running ? State.ERROR : State.IDLE;
                    detail = "tunnel closed: " + reason;
                }
                synchronized (done) { ended[0] = true; done.notifyAll(); }
            });
            mux = m;
            state = State.CONNECTED;
            detail = "connected";
            try { m.sendPing(); } catch (IOException ignored) {}
            synchronized (done) {
                while (!ended[0] && running) {
                    try { done.wait(1000); } catch (InterruptedException e) { return true; }
                }
            }
            return true;
        } finally {
            if (!handedOver) try { outer.close(); } catch (IOException ignored) {}
        }
    }
}
