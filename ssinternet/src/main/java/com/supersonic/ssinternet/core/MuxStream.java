package com.supersonic.ssinternet.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;

/** One TCP-like byte stream inside a MuxSession, with its own flow-control window. */
public final class MuxStream {
    final MuxSession session;
    final int id;

    private final ArrayDeque<byte[]> queue = new ArrayDeque<>();
    private byte[] cur;
    private int curOff;
    private int queuedBytes;
    private int consumed;
    private boolean remoteFin, reset, localFin;
    private int sendWindow = MuxSession.INIT_WINDOW;

    // result of OPEN as seen by the side that asked for it
    private int openState; // 0 pending, 1 ok, 2 refused
    private int openCode;
    private String openMessage = "";

    private final InputStream in = new InputStream() {
        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xff);
        }
        @Override public int read(byte[] b, int off, int len) throws IOException { return readImpl(b, off, len); }
        @Override public void close() { MuxStream.this.closeWrite(); }
    };

    private final OutputStream out = new OutputStream() {
        @Override public void write(int b) throws IOException { write(new byte[]{(byte) b}, 0, 1); }
        @Override public void write(byte[] b, int off, int len) throws IOException { writeImpl(b, off, len); }
        @Override public void close() { MuxStream.this.closeWrite(); }
    };

    MuxStream(MuxSession session, int id) {
        this.session = session;
        this.id = id;
    }

    public int id() { return id; }
    public InputStream getInputStream() { return in; }
    public OutputStream getOutputStream() { return out; }

    // ---------------------------------------------------------------- called by the session reader thread (never blocks)

    void deliver(byte[] data) {
        boolean overflow;
        synchronized (this) {
            if (reset || remoteFin) return;
            queue.add(data);
            queuedBytes += data.length;
            overflow = queuedBytes > MuxSession.INIT_WINDOW * 2;
            notifyAll();
        }
        if (overflow) session.close("peer ignored the flow-control window");
    }

    synchronized void onRemoteFin() { remoteFin = true; notifyAll(); }

    synchronized void onReset() { reset = true; notifyAll(); }

    synchronized void addWindow(int n) {
        long w = (long) sendWindow + n;
        sendWindow = (int) Math.min(w, Integer.MAX_VALUE / 2);
        notifyAll();
    }

    synchronized void onOpenResult(boolean ok, int code, String message) {
        openState = ok ? 1 : 2;
        openCode = code;
        openMessage = message == null ? "" : message;
        notifyAll();
    }

    synchronized void sessionClosed() { notifyAll(); }

    // ---------------------------------------------------------------- opening

    void awaitOpen(int timeoutMs) throws IOException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        synchronized (this) {
            while (openState == 0 && !session.isClosed()) {
                long left = deadline - System.currentTimeMillis();
                if (left <= 0) break;
                try { wait(left); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            }
            if (openState == 1) return;
            if (openState == 2) throw new MuxSession.OpenRefused(openCode, openMessage);
        }
        abort();
        throw new MuxSession.OpenRefused(MuxSession.ERR_TIMEOUT, session.isClosed() ? "tunnel closed" : "provider did not answer");
    }

    /** Provider side: the outbound connection is up. */
    public void acceptOpen() throws IOException { session.sendFrame(MuxSession.T_OPEN_OK, id, null, 0, 0); }

    /** Provider side: refuse and forget the stream. */
    public void rejectOpen(int code, String message) {
        byte[] m = (message == null ? "" : message).getBytes(java.nio.charset.Charset.forName("UTF-8"));
        byte[] p = new byte[1 + Math.min(m.length, 200)];
        p[0] = (byte) code;
        System.arraycopy(m, 0, p, 1, p.length - 1);
        try { session.sendFrame(MuxSession.T_OPEN_ERR, id, p, 0, p.length); } catch (IOException ignored) {}
        synchronized (this) { reset = true; notifyAll(); }
        session.removeStream(id);
    }

    // ---------------------------------------------------------------- read / write

    private int readImpl(byte[] b, int off, int len) throws IOException {
        if (len == 0) return 0;
        int credit = 0;
        int n;
        synchronized (this) {
            while (cur == null && queue.isEmpty() && !remoteFin && !reset && !session.isClosed()) {
                try { wait(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException("interrupted"); }
            }
            if (reset) throw new IOException("stream reset");
            if (cur == null) {
                cur = queue.poll();
                curOff = 0;
                if (cur == null) {
                    if (remoteFin) return -1;
                    throw new IOException("tunnel closed");
                }
            }
            n = Math.min(len, cur.length - curOff);
            System.arraycopy(cur, curOff, b, off, n);
            curOff += n;
            queuedBytes -= n;
            if (curOff == cur.length) cur = null;
            consumed += n;
            if (consumed >= MuxSession.INIT_WINDOW / 4) {
                credit = consumed;
                consumed = 0;
            }
        }
        if (credit > 0) {
            byte[] p = {(byte) (credit >>> 24), (byte) (credit >>> 16), (byte) (credit >>> 8), (byte) credit};
            try { session.sendFrame(MuxSession.T_WINDOW, id, p, 0, 4); } catch (IOException ignored) {}
        }
        return n;
    }

    private void writeImpl(byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            int n;
            synchronized (this) {
                long deadline = System.currentTimeMillis() + 120_000;
                while (sendWindow == 0 && !reset && !localFin && !session.isClosed()) {
                    if (System.currentTimeMillis() > deadline) throw new IOException("peer stopped reading (write stalled)");
                    try { wait(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException("interrupted"); }
                }
                if (reset) throw new IOException("stream reset");
                if (localFin) throw new IOException("stream closed");
                if (session.isClosed()) throw new IOException("tunnel closed");
                n = Math.min(Math.min(len, sendWindow), MuxSession.MAX_FRAME);
                sendWindow -= n;
            }
            session.sendFrame(MuxSession.T_DATA, id, b, off, n);
            session.stats.sent.addAndGet(n);
            off += n;
            len -= n;
        }
    }

    // ---------------------------------------------------------------- closing

    /** Half close: no more data from us. The other direction stays open. */
    public void closeWrite() {
        synchronized (this) {
            if (localFin || reset) return;
            localFin = true;
            notifyAll();
        }
        try { session.sendFrame(MuxSession.T_FIN, id, null, 0, 0); } catch (IOException ignored) {}
        maybeRemove();
    }

    /** Hard close in both directions. */
    public void abort() {
        synchronized (this) {
            if (reset) return;
            reset = true;
            notifyAll();
        }
        try { session.sendFrame(MuxSession.T_RST, id, null, 0, 0); } catch (IOException ignored) {}
        session.removeStream(id);
    }

    void maybeRemove() {
        boolean done;
        synchronized (this) { done = localFin && remoteFin; }
        if (done) session.removeStream(id);
    }

    synchronized boolean isReset() { return reset; }
}
