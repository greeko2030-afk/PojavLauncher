package com.supersonic.ssinternet.core;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Multiplexes many byte streams over ONE (TLS) connection, so a 300 ms round trip Dhaka - London
 * is paid once per tunnel and not once per website connection.
 *
 * Frame: type(1) stream(4) length(4) payload. Every stream has a credit window; a slow stream
 * therefore can not block the others or fill the phone's memory. The reader thread never writes
 * (writes can block on TCP), which rules out the classic mutual-write deadlock.
 */
public final class MuxSession implements Closeable {
    public static final int MAX_FRAME = 16384;
    public static final int INIT_WINDOW = 131072;
    public static final int MAX_STREAMS = 128;

    static final int T_OPEN = 1, T_OPEN_OK = 2, T_OPEN_ERR = 3, T_DATA = 4, T_WINDOW = 5, T_FIN = 6, T_RST = 7,
            T_PING = 8, T_PONG = 9, T_SPEED_REQ = 10, T_SPEED_DATA = 11, T_SPEED_END = 12;

    public static final int ERR_BUSY = 1, ERR_DENIED = 2, ERR_UNREACHABLE = 3, ERR_REFUSED = 4, ERR_TIMEOUT = 5, ERR_CAP = 6;

    private static final Charset UTF8 = Charset.forName("UTF-8");

    public static final class OpenRefused extends IOException {
        public final int code;
        public OpenRefused(int code, String msg) { super(msg); this.code = code; }
    }

    public interface Handler {
        /** Provider side. Must return quickly; do the real work on another thread, then acceptOpen()/rejectOpen(). */
        void onOpen(MuxStream stream, String host, int port);
    }

    public interface CloseListener {
        void onClosed(MuxSession session, String reason);
    }

    private final Socket sock;
    private final DataInputStream in;
    private final OutputStream out;
    private final Object wlock = new Object();
    private final byte[] wh = new byte[9];
    private final boolean isClient;
    private final Handler handler;
    private final Executor pool;
    private final ConcurrentHashMap<Integer, MuxStream> streams = new ConcurrentHashMap<>();
    private final AtomicInteger nextId = new AtomicInteger(1);
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile String closeReason = "";
    private volatile CloseListener closeListener;
    public final Stats stats = new Stats();
    private volatile long rttNanos = -1;
    private volatile long lastReadMillis = System.currentTimeMillis();

    // speed test (download direction)
    private final Object speedLock = new Object();
    private long speedGot;
    private boolean speedDone;
    private final AtomicBoolean speedServing = new AtomicBoolean();

    public MuxSession(Socket sock, boolean isClient, Handler handler, Executor pool) throws IOException {
        this.sock = sock;
        this.isClient = isClient;
        this.handler = handler;
        this.pool = pool;
        this.in = new DataInputStream(sock.getInputStream());
        this.out = new BufferedOutputStream(sock.getOutputStream(), MAX_FRAME + 64);
        Thread t = new Thread(this::readLoop, "ss-mux-reader");
        t.setDaemon(true);
        t.start();
    }

    public void setCloseListener(CloseListener l) { this.closeListener = l; }

    public boolean isClosed() { return closed.get(); }

    public String closeReason() { return closeReason; }

    public int streamCount() { return streams.size(); }

    /** Round trip time to the other end of the tunnel in milliseconds, or -1 if not measured yet. */
    public long rttMillis() { long r = rttNanos; return r < 0 ? -1 : Math.max(1, r / 1_000_000L); }

    public long millisSinceLastRead() { return System.currentTimeMillis() - lastReadMillis; }

    // ---------------------------------------------------------------- client API

    public MuxStream open(String host, int port, int timeoutMs) throws IOException {
        if (!isClient) throw new IllegalStateException("only the client opens streams");
        byte[] h = host.getBytes(UTF8);
        if (h.length == 0 || h.length > 253) throw new IOException("bad host name");
        if (streams.size() >= MAX_STREAMS) throw new OpenRefused(ERR_BUSY, "too many open connections");
        int id = nextId.getAndAdd(2);
        MuxStream st = new MuxStream(this, id);
        streams.put(id, st);
        byte[] p = new byte[2 + h.length];
        p[0] = (byte) (port >> 8);
        p[1] = (byte) port;
        System.arraycopy(h, 0, p, 2, h.length);
        try {
            sendFrame(T_OPEN, id, p, 0, p.length);
        } catch (IOException e) {
            streams.remove(id);
            throw e;
        }
        st.awaitOpen(timeoutMs);
        return st;
    }

    public void sendPing() throws IOException {
        long t = System.nanoTime();
        byte[] p = new byte[8];
        for (int i = 0; i < 8; i++) p[i] = (byte) (t >>> (56 - 8 * i));
        sendFrame(T_PING, 0, p, 0, 8);
    }

    /** Measures real throughput provider -> client through this tunnel. Returns bytes per second. */
    public double speedTest(int bytes, int timeoutMs) throws IOException {
        if (bytes < 1024 || bytes > 16 * 1024 * 1024) throw new IllegalArgumentException("bytes");
        synchronized (speedLock) {
            speedGot = 0;
            speedDone = false;
        }
        long start = System.nanoTime();
        byte[] p = {(byte) (bytes >>> 24), (byte) (bytes >>> 16), (byte) (bytes >>> 8), (byte) bytes};
        sendFrame(T_SPEED_REQ, 0, p, 0, 4);
        long deadline = System.currentTimeMillis() + timeoutMs;
        synchronized (speedLock) {
            while (!speedDone && !isClosed()) {
                long left = deadline - System.currentTimeMillis();
                if (left <= 0) throw new IOException("speed test timed out");
                try { speedLock.wait(left); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException("interrupted"); }
            }
            if (!speedDone) throw new IOException("tunnel closed");
            double secs = (System.nanoTime() - start) / 1e9;
            return speedGot / Math.max(secs, 0.001);
        }
    }

    // ---------------------------------------------------------------- framing

    void sendFrame(int type, int id, byte[] p, int off, int len) throws IOException {
        if (closed.get()) throw new IOException("tunnel closed");
        try {
            synchronized (wlock) {
                wh[0] = (byte) type;
                wh[1] = (byte) (id >>> 24); wh[2] = (byte) (id >>> 16); wh[3] = (byte) (id >>> 8); wh[4] = (byte) id;
                wh[5] = (byte) (len >>> 24); wh[6] = (byte) (len >>> 16); wh[7] = (byte) (len >>> 8); wh[8] = (byte) len;
                out.write(wh, 0, 9);
                if (len > 0) out.write(p, off, len);
                out.flush();
            }
        } catch (IOException e) {
            close("write failed: " + e.getMessage());
            throw e;
        }
    }

    private void readLoop() {
        byte[] hdr = new byte[9];
        byte[] buf = new byte[MAX_FRAME];
        try {
            while (!closed.get()) {
                in.readFully(hdr);
                lastReadMillis = System.currentTimeMillis();
                int type = hdr[0] & 0xff;
                int id = ((hdr[1] & 0xff) << 24) | ((hdr[2] & 0xff) << 16) | ((hdr[3] & 0xff) << 8) | (hdr[4] & 0xff);
                int len = ((hdr[5] & 0xff) << 24) | ((hdr[6] & 0xff) << 16) | ((hdr[7] & 0xff) << 8) | (hdr[8] & 0xff);
                if (len < 0 || len > MAX_FRAME) throw new IOException("bad frame length");
                if (len > 0) in.readFully(buf, 0, len);
                dispatch(type, id, buf, len);
            }
        } catch (IOException | RuntimeException e) {
            close(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
    }

    private void dispatch(int type, int id, byte[] buf, int len) throws IOException {
        switch (type) {
            case T_OPEN: {
                if (isClient || handler == null || len < 3 || (id & 1) == 0) throw new IOException("protocol error: OPEN");
                final int port = ((buf[0] & 0xff) << 8) | (buf[1] & 0xff);
                final String host = new String(buf, 2, len - 2, UTF8);
                if (streams.containsKey(id)) throw new IOException("protocol error: duplicate stream");
                final MuxStream st = new MuxStream(this, id);
                if (streams.size() >= MAX_STREAMS) {
                    pool.execute(() -> st.rejectOpen(ERR_BUSY, "provider has too many open connections"));
                    return;
                }
                streams.put(id, st);
                handler.onOpen(st, host, port);
                return;
            }
            case T_OPEN_OK: {
                MuxStream s = streams.get(id);
                if (s != null) s.onOpenResult(true, 0, "");
                return;
            }
            case T_OPEN_ERR: {
                MuxStream s = streams.get(id);
                if (s != null) {
                    int code = len > 0 ? buf[0] & 0xff : ERR_UNREACHABLE;
                    s.onOpenResult(false, code, len > 1 ? new String(buf, 1, len - 1, UTF8) : "refused");
                    removeStream(id);
                }
                return;
            }
            case T_DATA: {
                MuxStream s = streams.get(id);
                stats.received.addAndGet(len);
                if (s != null) s.deliver(Arrays.copyOf(buf, len));
                return;
            }
            case T_WINDOW: {
                MuxStream s = streams.get(id);
                if (s != null && len == 4) {
                    int n = ((buf[0] & 0xff) << 24) | ((buf[1] & 0xff) << 16) | ((buf[2] & 0xff) << 8) | (buf[3] & 0xff);
                    if (n > 0) s.addWindow(n);
                }
                return;
            }
            case T_FIN: {
                MuxStream s = streams.get(id);
                if (s != null) { s.onRemoteFin(); s.maybeRemove(); }
                return;
            }
            case T_RST: {
                MuxStream s = streams.get(id);
                if (s != null) { s.onReset(); removeStream(id); }
                return;
            }
            case T_PING: {
                final byte[] echo = Arrays.copyOf(buf, len);
                pool.execute(() -> { try { sendFrame(T_PONG, 0, echo, 0, echo.length); } catch (IOException ignored) {} });
                return;
            }
            case T_PONG: {
                if (len == 8) {
                    long t = 0;
                    for (int i = 0; i < 8; i++) t = (t << 8) | (buf[i] & 0xff);
                    rttNanos = System.nanoTime() - t;
                }
                return;
            }
            case T_SPEED_REQ: {
                if (isClient || len != 4) return;
                final int n = ((buf[0] & 0xff) << 24) | ((buf[1] & 0xff) << 16) | ((buf[2] & 0xff) << 8) | (buf[3] & 0xff);
                if (n < 1024 || n > 16 * 1024 * 1024 || !speedServing.compareAndSet(false, true)) return;
                pool.execute(() -> {
                    try {
                        byte[] chunk = new byte[MAX_FRAME];
                        new java.security.SecureRandom().nextBytes(chunk);
                        int left = n;
                        while (left > 0 && !isClosed()) {
                            int k = Math.min(left, MAX_FRAME);
                            sendFrame(T_SPEED_DATA, 0, chunk, 0, k);
                            stats.sent.addAndGet(k);
                            left -= k;
                        }
                        sendFrame(T_SPEED_END, 0, null, 0, 0);
                    } catch (IOException ignored) {
                    } finally {
                        speedServing.set(false);
                    }
                });
                return;
            }
            case T_SPEED_DATA: {
                stats.received.addAndGet(len);
                synchronized (speedLock) { speedGot += len; }
                return;
            }
            case T_SPEED_END: {
                synchronized (speedLock) { speedDone = true; speedLock.notifyAll(); }
                return;
            }
            default:
                // unknown frame types are ignored so newer peers can add features
        }
    }

    void removeStream(int id) { streams.remove(id); }

    // ---------------------------------------------------------------- closing

    public void close(String reason) {
        if (!closed.compareAndSet(false, true)) return;
        closeReason = reason == null ? "" : reason;
        try { sock.close(); } catch (IOException ignored) {}
        for (MuxStream s : streams.values()) s.sessionClosed();
        streams.clear();
        synchronized (speedLock) { speedLock.notifyAll(); }
        CloseListener l = closeListener;
        if (l != null) l.onClosed(this, closeReason);
    }

    @Override public void close() { close("closed locally"); }
}
