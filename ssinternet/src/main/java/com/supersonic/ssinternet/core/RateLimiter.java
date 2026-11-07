package com.supersonic.ssinternet.core;

/** Token-bucket style throttle shared by all streams of one client. bytesPerSec <= 0 means unlimited. */
public final class RateLimiter {
    private volatile long bytesPerSec;
    private long nextFreeNanos;

    public RateLimiter(long bytesPerSec) { this.bytesPerSec = bytesPerSec; }

    public void setRate(long bytesPerSec) { this.bytesPerSec = bytesPerSec; }

    public void acquire(int n) throws InterruptedException {
        long rate = bytesPerSec;
        if (rate <= 0 || n <= 0) return;
        long wait;
        synchronized (this) {
            long now = System.nanoTime();
            if (nextFreeNanos < now) nextFreeNanos = now;
            wait = nextFreeNanos - now;
            nextFreeNanos += (long) (n * 1e9 / rate);
        }
        if (wait > 20_000_000L) Thread.sleep(wait / 1_000_000L, (int) (wait % 1_000_000L));
    }
}
