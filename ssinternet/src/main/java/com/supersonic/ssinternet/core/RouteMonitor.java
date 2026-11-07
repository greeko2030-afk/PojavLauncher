package com.supersonic.ssinternet.core;

/**
 * Decides where the app's OWN traffic (mod browsing, downloads, ...) goes right now:
 * through the provider's connection, directly (fallback), or nowhere (fallback off).
 * Raises one "problem" event when the provider's connection fails and one "recovered" event when it is back.
 */
public final class RouteMonitor {
    public enum Status { STARTING, UP, DOWN }
    public enum Route { TUNNEL, DIRECT, BLOCKED }

    public interface Health {
        boolean usable();
        boolean connecting();
    }

    public interface Listener {
        void onProblem();
        void onRecovered();
    }

    private final Health health;
    private final Listener listener;
    private final long graceMillis;
    private final long startedAt = System.currentTimeMillis();
    private volatile Status status = Status.STARTING;
    private volatile boolean fallbackToOwnInternet = true;
    private volatile boolean enabled = true;
    private volatile boolean stopped;
    private boolean everDown;

    public RouteMonitor(Health health, Listener listener, long graceMillis) {
        this.health = health;
        this.listener = listener;
        this.graceMillis = graceMillis;
        Thread t = new Thread(() -> {
            while (!stopped) {
                tick();
                try { Thread.sleep(500); } catch (InterruptedException e) { return; }
            }
        }, "ss-route-monitor");
        t.setDaemon(true);
        t.start();
    }

    public void setFallbackToOwnInternet(boolean v) { fallbackToOwnInternet = v; }
    public void setEnabled(boolean v) { enabled = v; }
    public Status status() { return status; }
    public void stop() { stopped = true; }

    public Route route() {
        if (!enabled) return Route.DIRECT;
        if (status != Status.DOWN) return Route.TUNNEL; // STARTING: the local proxy waits for the tunnel
        return fallbackToOwnInternet ? Route.DIRECT : Route.BLOCKED;
    }

    /** Package-visible so tests can drive it without waiting. */
    void tick() {
        boolean usable = health.usable();
        Status old = status;
        if (usable) {
            status = Status.UP;
            if (old == Status.DOWN && everDown) listener.onRecovered();
        } else if (old == Status.UP) {
            status = Status.DOWN;
            everDown = true;
            listener.onProblem();
        } else if (old == Status.STARTING) {
            boolean graceOver = System.currentTimeMillis() - startedAt > graceMillis;
            if (graceOver || !health.connecting()) {
                status = Status.DOWN;
                everDown = true;
                listener.onProblem();
            }
        }
    }
}
