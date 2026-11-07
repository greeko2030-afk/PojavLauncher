package com.supersonic.ssinternet.core;

import java.util.concurrent.atomic.AtomicLong;

/** Real byte counters. Rates are measured over the last tick interval, not estimated. */
public final class Stats {
    public final AtomicLong received = new AtomicLong();
    public final AtomicLong sent = new AtomicLong();
    private long lastRx, lastTx, lastT;
    private volatile long rxRate, txRate;

    /** Call about once per second. */
    public synchronized void tick() {
        long now = System.nanoTime();
        long rx = received.get(), tx = sent.get();
        if (lastT != 0) {
            double dt = (now - lastT) / 1e9;
            if (dt > 0.05) {
                rxRate = (long) ((rx - lastRx) / dt);
                txRate = (long) ((tx - lastTx) / dt);
            }
        }
        lastRx = rx;
        lastTx = tx;
        lastT = now;
    }

    /** Bytes per second received from the peer over the last interval. */
    public long rxRate() { return rxRate; }

    /** Bytes per second sent to the peer over the last interval. */
    public long txRate() { return txRate; }
}
