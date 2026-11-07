package com.supersonic.ssinternet.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Copies bytes between a normal socket and a tunnel stream, in both directions. */
public final class Pipes {
    private Pipes() {}

    /** Called for every chunk before it is forwarded: throttling and data caps live here. */
    public interface Gate {
        void pass(int bytes) throws IOException, InterruptedException;
    }

    public static final Gate OPEN = new Gate() {
        @Override public void pass(int bytes) {}
    };

    public static void bridge(final Socket sock, final MuxStream st, final Gate gate, final Executor pool) {
        final AtomicInteger running = new AtomicInteger(2);
        final AtomicBoolean failed = new AtomicBoolean();
        final Runnable finish = () -> {
            if (running.decrementAndGet() == 0) {
                try { sock.close(); } catch (IOException ignored) {}
                if (failed.get()) st.abort();
            }
        };
        pool.execute(() -> { // local socket -> tunnel
            try {
                InputStream in = sock.getInputStream();
                OutputStream out = st.getOutputStream();
                byte[] buf = new byte[MuxSession.MAX_FRAME];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    if (n == 0) continue;
                    gate.pass(n);
                    out.write(buf, 0, n);
                }
                st.closeWrite();
            } catch (IOException | InterruptedException e) {
                failed.set(true);
                st.abort();
                try { sock.close(); } catch (IOException ignored) {}
            } finally {
                finish.run();
            }
        });
        pool.execute(() -> { // tunnel -> local socket
            try {
                InputStream in = st.getInputStream();
                OutputStream out = sock.getOutputStream();
                byte[] buf = new byte[MuxSession.MAX_FRAME];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    if (n == 0) continue;
                    gate.pass(n);
                    out.write(buf, 0, n);
                    out.flush();
                }
                try { sock.shutdownOutput(); } catch (IOException ignored) {}
            } catch (IOException | InterruptedException e) {
                failed.set(true);
                st.abort();
                try { sock.close(); } catch (IOException ignored) {}
            } finally {
                finish.run();
            }
        });
    }
}
