package com.supersonic.ssinternet.core;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Install with ProxySelector.setDefault(...). Every java.net / OkHttp request of the process then follows
 * RouteMonitor: through the local SS Internet proxy, or direct when the fallback is active.
 * Local and private destinations are never tunnelled.
 */
public final class SsProxySelector extends ProxySelector {
    public interface PortSource {
        int port();
    }

    private final RouteMonitor monitor;
    private final PortSource port;

    public SsProxySelector(RouteMonitor monitor, PortSource port) {
        this.monitor = monitor;
        this.port = port;
    }

    @Override
    public List<Proxy> select(URI uri) {
        String host = uri == null ? null : uri.getHost();
        if (host == null || isLocal(host)) return Collections.singletonList(Proxy.NO_PROXY);
        RouteMonitor.Route r = monitor.route();
        int p = port.port();
        if (r == RouteMonitor.Route.DIRECT || p <= 0) return Collections.singletonList(Proxy.NO_PROXY);
        // TUNNEL and BLOCKED both use the local proxy; when blocked it refuses the connection.
        List<Proxy> out = new ArrayList<>();
        out.add(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", p)));
        return out;
    }

    @Override
    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {}

    static boolean isLocal(String host) {
        String h = host.toLowerCase(Locale.US);
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length() - 1);
        if (h.equals("localhost") || h.endsWith(".local") || h.endsWith(".localhost")) return true;
        boolean literal = h.indexOf(':') >= 0 || h.matches("[0-9.]+");
        if (!literal) return false;
        try {
            return !EgressPolicy.isPublic(java.net.InetAddress.getByName(h));
        } catch (java.net.UnknownHostException e) {
            return false;
        }
    }
}
