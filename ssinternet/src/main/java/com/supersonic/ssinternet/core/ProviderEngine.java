package com.supersonic.ssinternet.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

/**
 * Provider mode: shares THIS device's internet connection with approved devices anywhere in the world.
 * Needs no public IP, no port forwarding, no hotspot: it only makes outbound connections to the relay.
 */
public final class ProviderEngine {
    public enum State { OFF, CONNECTING, ONLINE, ERROR }

    public static final class Config {
        public String name = "SS Internet";
        public String country = "";
        public boolean listed = true;
        /** Open mode: unknown devices are let in automatically (still blockable, limited, removable). */
        public boolean autoApprove = false;
        public int maxClients = 5;
        /** Per client, both directions together. 0 = unlimited. */
        public long perClientBytesPerSec = 0;
        /** Per client, per provider run. 0 = unlimited. */
        public long perClientCapBytes = 0;
        /** All clients together, per provider run. 0 = unlimited. */
        public long totalCapBytes = 0;
        public EgressPolicy policy = new EgressPolicy();
    }

    public interface Listener {
        /** Short human readable events, e.g. a new device asking for approval. Called from background threads. */
        void onEvent(String message);
    }

    public static final class ClientInfo {
        public final String id, label;
        public final long connectedMillis;
        /** Bytes the provider sent to the client (the client's download). */
        public final long downBytes;
        /** Bytes the provider received from the client (the client's upload). */
        public final long upBytes;
        public final long downRate, upRate;
        public final int streams;
        public final long rttMillis;
        ClientInfo(String id, String label, long connectedMillis, long down, long up, long downRate, long upRate, int streams, long rtt) {
            this.id = id; this.label = label; this.connectedMillis = connectedMillis; this.downBytes = down; this.upBytes = up;
            this.downRate = downRate; this.upRate = upRate; this.streams = streams; this.rttMillis = rtt;
        }
    }

    private final class ClientSession implements Pipes.Gate {
        final String id;
        final long since = System.currentTimeMillis();
        final MuxSession mux;
        final RateLimiter limiter;
        final AtomicLong used = new AtomicLong();

        ClientSession(String id, MuxSession mux, RateLimiter limiter) {
            this.id = id;
            this.mux = mux;
            this.limiter = limiter;
        }

        @Override public void pass(int bytes) throws IOException, InterruptedException {
            limiter.acquire(bytes);
            long u = used.addAndGet(bytes);
            long t = totalBytes.addAndGet(bytes);
            if (config.perClientCapBytes > 0 && u > config.perClientCapBytes) throw new IOException("client data cap reached");
            if (config.totalCapBytes > 0 && t > config.totalCapBytes) throw new IOException("provider data cap reached");
        }

        boolean capReached() {
            return (config.perClientCapBytes > 0 && used.get() >= config.perClientCapBytes)
                    || (config.totalCapBytes > 0 && totalBytes.get() >= config.totalCapBytes);
        }
    }

    private final Identity identity;
    private final Config config;
    private final RelayLink link;
    private final ApprovalStore approvals;
    private final Listener listener;
    private final File usageFile;
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "ss-provider");
        t.setDaemon(true);
        return t;
    });
    private final ScheduledExecutorService ticker = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ss-provider-tick");
        t.setDaemon(true);
        return t;
    });
    private final ConcurrentHashMap<String, ClientSession> active = new ConcurrentHashMap<>();
    private final AtomicLong totalBytes = new AtomicLong();
    private volatile long lifetimeBase;
    private volatile State state = State.OFF;
    private volatile String detail = "";
    private volatile boolean running;
    private volatile SSLSocket control;
    private SSLContext innerCtx;
    private Thread controlThread;

    public ProviderEngine(File dir, Identity identity, String relayHost, int relayPort, String relayPin,
                          Config config, Listener listener) throws IOException, java.security.GeneralSecurityException {
        this.identity = identity;
        this.config = config;
        this.listener = listener;
        this.link = new RelayLink(relayHost, relayPort, relayPin, identity);
        this.approvals = new ApprovalStore(new File(dir, "approvals.txt"));
        this.usageFile = new File(dir, "provider-usage.properties");
        this.lifetimeBase = loadLifetime();
    }

    // ------------------------------------------------------------------ public API

    public String deviceId() { return identity.id; }
    public State state() { return state; }
    public String detail() { return detail; }
    public ApprovalStore approvals() { return approvals; }

    /** Bytes forwarded for clients since start(). */
    public long sessionBytes() { return totalBytes.get(); }

    /** Bytes forwarded for clients, all runs together. */
    public long lifetimeBytes() { return lifetimeBase + totalBytes.get(); }

    public synchronized void start() {
        if (running) return;
        running = true;
        totalBytes.set(0);
        lifetimeBase = loadLifetime();
        try {
            innerCtx = TlsUtil.context(identity, new TrustManager[]{new TlsUtil.AnyClientTrustManager()});
        } catch (Exception e) {
            running = false;
            setState(State.ERROR, "TLS setup failed: " + e.getMessage());
            return;
        }
        ticker.scheduleWithFixedDelay(this::tick, 1, 1, TimeUnit.SECONDS);
        controlThread = new Thread(this::controlLoop, "ss-provider-control");
        controlThread.setDaemon(true);
        controlThread.start();
    }

    public synchronized void stop() {
        if (!running) return;
        running = false;
        SSLSocket c = control;
        if (c != null) {
            try { LineIO.writeLine(c.getOutputStream(), "BYE"); } catch (IOException ignored) {}
            try { c.close(); } catch (IOException ignored) {}
        }
        for (ClientSession s : active.values()) s.mux.close("provider stopped");
        active.clear();
        saveLifetime();
        setState(State.OFF, "");
    }

    /** Applies a changed name / listing to the relay without reconnecting. */
    public void updateListing() {
        SSLSocket c = control;
        if (c == null) return;
        try {
            synchronized (c) { LineIO.writeLine(c.getOutputStream(), "UPDATE " + listingTokens()); }
        } catch (IOException ignored) {}
    }

    public List<ClientInfo> clients() {
        List<ClientInfo> out = new ArrayList<>();
        Map<String, String> labels = approvals.approvedMap();
        for (ClientSession s : active.values()) {
            String label = labels.get(s.id);
            out.add(new ClientInfo(s.id, label == null ? "" : label, System.currentTimeMillis() - s.since,
                    s.mux.stats.sent.get(), s.mux.stats.received.get(), s.mux.stats.txRate(), s.mux.stats.rxRate(),
                    s.mux.streamCount(), s.mux.rttMillis()));
        }
        return out;
    }

    public int connectedCount() { return active.size(); }

    public long totalDownRate() { long r = 0; for (ClientSession s : active.values()) r += s.mux.stats.txRate(); return r; }
    public long totalUpRate() { long r = 0; for (ClientSession s : active.values()) r += s.mux.stats.rxRate(); return r; }

    public List<ApprovalStore.Pending> pending() { return approvals.pending(); }

    public void approve(String id, String label) { approvals.approve(Identity.normalizeId(id), label); }

    public void deny(String id) {
        String n = Identity.normalizeId(id);
        approvals.block(n);
        ClientSession s = active.get(n);
        if (s != null) s.mux.close("blocked by provider");
    }

    /** Removes the approval and disconnects the device. */
    public void revoke(String id) {
        String n = Identity.normalizeId(id);
        approvals.forget(n);
        ClientSession s = active.get(n);
        if (s != null) s.mux.close("approval revoked");
    }

    // ------------------------------------------------------------------ internals

    private void setState(State s, String d) {
        state = s;
        detail = d == null ? "" : d;
    }

    private void event(String m) {
        if (listener != null) try { listener.onEvent(m); } catch (RuntimeException ignored) {}
    }

    private String listingTokens() {
        return "name=" + Codec.urlEncode(config.name) + " country=" + (config.country.isEmpty() ? "-" : config.country)
                + " listed=" + (config.listed ? "1" : "0") + " max=" + config.maxClients;
    }

    private void tick() {
        try {
            long now = 0;
            for (ClientSession s : active.values()) {
                s.mux.stats.tick();
                if (s.mux.millisSinceLastRead() > 15_000) s.mux.close("no data from client for 15 s");
                else if (s.capReached()) s.mux.close("data cap reached");
            }
            if ((++tickCount % 5) == 0) {
                for (ClientSession s : active.values()) try { s.mux.sendPing(); } catch (IOException ignored) {}
            }
            if ((tickCount % 30) == 0) saveLifetime();
        } catch (RuntimeException ignored) {}
    }

    private int tickCount;

    private void controlLoop() {
        long backoff = 1000;
        while (running) {
            SSLSocket c = null;
            try {
                setState(State.CONNECTING, "connecting to relay");
                c = link.connect();
                control = c;
                InputStream in = c.getInputStream();
                RelayLink.hello(c, "PROVIDER", null);
                synchronized (c) { LineIO.writeLine(c.getOutputStream(), "REGISTER " + listingTokens()); }
                String ok = LineIO.readLine(in, 256);
                if (!ok.equals("OK")) throw new IOException("relay: " + ok);
                c.setSoTimeout(0);
                setState(State.ONLINE, "online");
                backoff = 1000;
                while (running) {
                    String line = LineIO.readLine(in, 512);
                    if (line.equals("PING")) {
                        synchronized (c) { LineIO.writeLine(c.getOutputStream(), "PONG"); }
                    } else if (line.startsWith("INCOMING ")) {
                        String[] p = line.split(" ");
                        if (p.length == 3 && p[1].matches("[0-9a-f]{32}")) {
                            final String sid = p[1];
                            pool.execute(() -> handleSession(sid));
                        }
                    }
                }
            } catch (IOException | RuntimeException e) {
                if (running) setState(State.ERROR, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            } finally {
                control = null;
                if (c != null) try { c.close(); } catch (IOException ignored) {}
            }
            if (!running) return;
            try { Thread.sleep(backoff + (long) (Math.random() * 500)); } catch (InterruptedException e) { return; }
            backoff = Math.min(backoff * 2, 30_000);
        }
    }

    private void handleSession(String sid) {
        SSLSocket outer = null;
        SSLSocket inner = null;
        boolean keep = false;
        try {
            outer = link.connect();
            RelayLink.hello(outer, "ACCEPT", sid);
            inner = (SSLSocket) innerCtx.getSocketFactory().createSocket(outer, "ss-peer", outer.getPort(), true);
            inner.setUseClientMode(false);
            inner.setNeedClientAuth(true);
            TlsUtil.harden(inner);
            inner.setSoTimeout(20_000);
            inner.startHandshake();
            String clientId = TlsUtil.peerId(inner);
            java.io.OutputStream io = inner.getOutputStream();

            ApprovalStore.State st = approvals.state(clientId);
            if (st == ApprovalStore.State.BLOCKED) {
                LineIO.writeLine(io, "DENIED");
                return;
            }
            if (st == ApprovalStore.State.UNKNOWN && config.autoApprove) {
                approvals.approve(clientId, "auto-allowed");
                event("Device let in automatically: " + Identity.pretty(clientId).substring(0, 14));
                st = ApprovalStore.State.APPROVED;
            }
            if (st == ApprovalStore.State.UNKNOWN) {
                if (approvals.addPending(clientId)) event("Approval request from " + Identity.pretty(clientId));
                LineIO.writeLine(io, "PENDING");
                return;
            }
            if (!active.containsKey(clientId) && active.size() >= config.maxClients) {
                LineIO.writeLine(io, "BUSY");
                return;
            }
            if (config.totalCapBytes > 0 && totalBytes.get() >= config.totalCapBytes) {
                LineIO.writeLine(io, "FULL");
                return;
            }
            LineIO.writeLine(io, "OK");
            inner.setSoTimeout(0);

            final RateLimiter limiter = new RateLimiter(config.perClientBytesPerSec);
            final ClientSession[] holder = new ClientSession[1];
            MuxSession mux = new MuxSession(inner, false, (stream, host, port) -> pool.execute(() -> openOutbound(holder[0], stream, host, port)), pool);
            ClientSession cs = new ClientSession(clientId, mux, limiter);
            holder[0] = cs;
            keep = true;
            ClientSession old = active.put(clientId, cs);
            if (old != null) old.mux.close("replaced by a newer connection");
            mux.setCloseListener((m, reason) -> {
                active.remove(clientId, cs);
                event("Client left: " + Identity.pretty(clientId).substring(0, 14) + " (" + reason + ")");
            });
            event("Client connected: " + Identity.pretty(clientId).substring(0, 14));
        } catch (IOException | RuntimeException e) {
            // handshake failures from strangers are routine
        } finally {
            if (!keep) {
                if (inner != null) try { inner.close(); } catch (IOException ignored) {}
                if (outer != null) try { outer.close(); } catch (IOException ignored) {}
            }
        }
    }

    private void openOutbound(ClientSession cs, MuxStream stream, String host, int port) {
        if (cs == null || cs.capReached()) {
            stream.rejectOpen(MuxSession.ERR_CAP, "data cap reached");
            return;
        }
        Socket out;
        try {
            out = config.policy.connect(host, port, 10_000);
        } catch (EgressPolicy.Denied e) {
            stream.rejectOpen(MuxSession.ERR_DENIED, e.getMessage());
            return;
        } catch (UnknownHostException e) {
            stream.rejectOpen(MuxSession.ERR_UNREACHABLE, "cannot resolve " + host);
            return;
        } catch (SocketTimeoutException e) {
            stream.rejectOpen(MuxSession.ERR_TIMEOUT, "connection timed out");
            return;
        } catch (ConnectException e) {
            stream.rejectOpen(MuxSession.ERR_REFUSED, "connection refused");
            return;
        } catch (NoRouteToHostException e) {
            stream.rejectOpen(MuxSession.ERR_UNREACHABLE, "no route to host");
            return;
        } catch (IOException e) {
            stream.rejectOpen(MuxSession.ERR_UNREACHABLE, "cannot connect");
            return;
        }
        try {
            stream.acceptOpen();
        } catch (IOException e) {
            try { out.close(); } catch (IOException ignored) {}
            return;
        }
        Pipes.bridge(out, stream, cs, pool);
    }

    // ------------------------------------------------------------------ lifetime usage

    private long loadLifetime() {
        if (!usageFile.isFile()) return 0;
        try (FileInputStream in = new FileInputStream(usageFile)) {
            Properties p = new Properties();
            p.load(in);
            return Long.parseLong(p.getProperty("bytes", "0"));
        } catch (IOException | NumberFormatException e) {
            return 0;
        }
    }

    private synchronized void saveLifetime() {
        try (FileOutputStream out = new FileOutputStream(usageFile)) {
            Properties p = new Properties();
            p.setProperty("bytes", Long.toString(lifetimeBase + totalBytes.get()));
            p.store(out, null);
        } catch (IOException ignored) {}
    }
}
