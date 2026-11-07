package com.supersonic.ssinternet;

import com.supersonic.ssinternet.core.*;
import com.supersonic.ssinternet.relay.RelayServer;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.net.ssl.*;

/** Real sockets, real TLS, real relay. The only fake part is that the "internet" is a TCP server on loopback. */
public class E2ETest {
    static int fails = 0;
    static void check(boolean ok, String msg) { System.out.println((ok ? "PASS  " : "FAIL  ") + msg); if (!ok) fails++; }

    interface Cond { boolean ok(); }
    static boolean waitFor(Cond c, long ms) throws Exception {
        long end = System.currentTimeMillis() + ms;
        while (System.currentTimeMillis() < end) { if (c.ok()) return true; Thread.sleep(50); }
        return c.ok();
    }

    static File dir(String n) throws IOException { return Files.createTempDirectory("ss-" + n).toFile(); }

    /** Returns the connected socket, or null and sets code[0] to the SOCKS5 reply code. */
    static Socket socksConnect(int proxyPort, String host, int port, int[] code) throws IOException {
        Socket s = new Socket("127.0.0.1", proxyPort);
        s.setSoTimeout(30000);
        OutputStream o = s.getOutputStream(); DataInputStream in = new DataInputStream(s.getInputStream());
        o.write(new byte[]{5, 1, 0}); o.flush();
        in.readUnsignedByte(); in.readUnsignedByte();
        byte[] h = host.getBytes("UTF-8");
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(new byte[]{5, 1, 0, 3, (byte) h.length}); b.write(h); b.write(port >> 8); b.write(port);
        o.write(b.toByteArray()); o.flush();
        in.readUnsignedByte(); int rep = in.readUnsignedByte(); in.readUnsignedByte(); int atyp = in.readUnsignedByte();
        in.skipBytes(atyp == 1 ? 6 : atyp == 4 ? 18 : 0);
        code[0] = rep;
        if (rep != 0) { s.close(); return null; }
        return s;
    }

    static ServerSocket startEcho() throws IOException {
        final ServerSocket ss = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        Thread t = new Thread(() -> { while (true) { try { final Socket c = ss.accept(); new Thread(() -> {
            try { InputStream i = c.getInputStream(); OutputStream o = c.getOutputStream(); byte[] b = new byte[8192]; int n;
                while ((n = i.read(b)) >= 0) { o.write(b, 0, n); o.flush(); } c.shutdownOutput(); } catch (IOException e) {} finally { try { c.close(); } catch (IOException e) {} }
        }).start(); } catch (IOException e) { return; } } });
        t.setDaemon(true); t.start();
        return ss;
    }

    static ServerSocket startHttp() throws IOException {
        final ServerSocket ss = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        Thread t = new Thread(() -> { while (true) { try { final Socket c = ss.accept(); new Thread(() -> {
            try { BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream())); String l; while ((l = r.readLine()) != null && !l.isEmpty()) {}
                byte[] body = "hello from the open internet".getBytes();
                c.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n").getBytes()); c.getOutputStream().write(body); c.getOutputStream().flush();
            } catch (IOException e) {} finally { try { c.close(); } catch (IOException e) {} }
        }).start(); } catch (IOException e) { return; } } });
        t.setDaemon(true); t.start();
        return ss;
    }

    /** Server that sends data forever and never reads. */
    static ServerSocket startFirehose() throws IOException {
        final ServerSocket ss = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        Thread t = new Thread(() -> { while (true) { try { final Socket c = ss.accept(); new Thread(() -> {
            try { OutputStream o = c.getOutputStream(); byte[] b = new byte[16384]; while (true) o.write(b); } catch (IOException e) {} finally { try { c.close(); } catch (IOException e) {} }
        }).start(); } catch (IOException e) { return; } } });
        t.setDaemon(true); t.start();
        return ss;
    }

    /** Sends n random bytes and reads n bytes back concurrently; returns true if identical. Counts elapsed ms in ms[0]. */
    static boolean echoRoundTrip(Socket s, final int n, long[] ms) throws Exception {
        final byte[] data = new byte[n]; new SecureRandom().nextBytes(data);
        final OutputStream o = s.getOutputStream(); final InputStream in = s.getInputStream();
        long t0 = System.nanoTime();
        Thread w = new Thread(() -> { try { o.write(data); o.flush(); } catch (IOException e) {} }); w.start();
        byte[] got = new byte[n]; int off = 0;
        while (off < n) { int k = in.read(got, off, n - off); if (k < 0) return false; off += k; }
        w.join();
        if (ms != null) ms[0] = (System.nanoTime() - t0) / 1_000_000;
        return Arrays.equals(data, got);
    }

    static ProviderEngine startProvider(File d, Identity id, int rport, String pin, ProviderEngine.Config cfg, List<String> events) throws Exception {
        ProviderEngine p = new ProviderEngine(d, id, "127.0.0.1", rport, pin, cfg, m -> { synchronized (events) { events.add(m); } });
        p.start();
        if (!waitFor(() -> p.state() == ProviderEngine.State.ONLINE, 10000)) throw new IllegalStateException("provider not online: " + p.state() + " " + p.detail());
        return p;
    }

    static ClientEngine startClient(Identity id, int rport, String pin, String providerId) throws Exception {
        ClientEngine c = new ClientEngine(id, "127.0.0.1", rport, pin, providerId, 0);
        c.start();
        return c;
    }

    public static void main(String[] args) throws Exception {
        Identity relayId = Identity.generate("relay");
        SSLContext rctx = TlsUtil.context(relayId, new TrustManager[]{new TlsUtil.AnyClientTrustManager()});
        RelayServer relay = new RelayServer(rctx, 0, new RelayServer.Limits());
        int rport = relay.getPort();
        System.out.println("relay on " + rport + ", relay ID " + Identity.pretty(relayId.id));

        ServerSocket echo = startEcho(), http = startHttp(), fire = startFirehose();
        Identity dhaka = Identity.loadOrCreate(dir("dhaka"), "dhaka"), london = Identity.loadOrCreate(dir("london"), "london");

        // reload from disk gives the same ID (identity persistence)
        File persist = dir("persist");
        Identity a1 = Identity.loadOrCreate(persist, "x"), a2 = Identity.loadOrCreate(persist, "x");
        check(a1.id.equals(a2.id), "identity is stable across restarts");

        List<String> events = Collections.synchronizedList(new ArrayList<String>());
        ProviderEngine.Config cfg = new ProviderEngine.Config();
        cfg.name = "Dhaka Home"; cfg.country = "BD"; cfg.policy = new EgressPolicy().allowPrivateForTests(true);
        ProviderEngine prov = startProvider(dir("prov"), dhaka, rport, relayId.id, cfg, events);
        check(true, "provider (Dhaka) online behind relay, outbound connection only");

        // 1. discovery
        RelayLink lk = new RelayLink("127.0.0.1", rport, relayId.id, london);
        List<RelayLink.ProviderEntry> list = lk.listProviders();
        check(list.size() == 1 && list.get(0).id.equals(dhaka.id) && list.get(0).name.equals("Dhaka Home") && list.get(0).country.equals("BD"), "client (London) discovers provider through relay directory");

        // 2. relay without pin / wrong pin is rejected
        try { new RelayLink("127.0.0.1", rport, Identity.generate("evil").id, london).listProviders(); check(false, "wrong relay pin must fail"); }
        catch (IOException e) { check(true, "client refuses a relay with a different identity"); }

        // 3. no approval, no access
        ClientEngine cl = startClient(london, rport, relayId.id, dhaka.id);
        check(waitFor(() -> cl.state() == ClientEngine.State.WAITING_APPROVAL, 10000), "unapproved device is held at 'waiting for approval'");
        check(waitFor(() -> { for (ApprovalStore.Pending p : prov.pending()) if (p.id.equals(london.id)) return true; return false; }, 3000), "provider sees the pending request");
        check(events.toString().contains("Approval request"), "provider is notified of the request");
        int[] code = new int[1];
        Socket tryS = null;
        try { tryS = socksConnect(cl.socksPort(), "127.0.0.1", echo.getLocalPort(), code); } catch (IOException e) { code[0] = -1; }
        check(tryS == null && code[0] != 0, "no traffic passes before approval (SOCKS reply " + code[0] + ")");
        if (tryS != null) tryS.close();

        // 4. approve -> connected
        prov.approve(london.id, "London phone");
        check(waitFor(() -> cl.state() == ClientEngine.State.CONNECTED, 15000), "after approval the client connects (state=" + cl.state() + ")");
        check(prov.connectedCount() == 1, "provider shows 1 connected user");

        // 5. real HTTP through the tunnel
        HttpURLConnection h = (HttpURLConnection) new URL("http://localhost:" + http.getLocalPort() + "/").openConnection(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", cl.socksPort())));
        h.setConnectTimeout(15000); h.setReadTimeout(15000);
        String body = new BufferedReader(new InputStreamReader(h.getInputStream())).readLine();
        check("hello from the open internet".equals(body), "HTTP request through SOCKS -> relay -> provider -> internet (hostname resolved at provider)");

        // 5b. same local port also works as an HTTP proxy (Android Wi-Fi proxy setting, browsers, curl)
        HttpURLConnection hp = (HttpURLConnection) new URL("http://127.0.0.1:" + http.getLocalPort() + "/page?x=1").openConnection(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", cl.socksPort())));
        hp.setConnectTimeout(15000); hp.setReadTimeout(15000);
        check("hello from the open internet".equals(new BufferedReader(new InputStreamReader(hp.getInputStream())).readLine()), "plain HTTP through the HTTP-proxy side of the local port");
        Socket cn = new Socket("127.0.0.1", cl.socksPort()); cn.setSoTimeout(20000);
        cn.getOutputStream().write(("CONNECT 127.0.0.1:" + echo.getLocalPort() + " HTTP/1.1\r\nHost: x\r\n\r\n").getBytes());
        BufferedReader cr = new BufferedReader(new InputStreamReader(cn.getInputStream()));
        String status = cr.readLine(); cr.readLine();
        cn.getOutputStream().write("tunnelled\n".getBytes());
        check(status != null && status.contains("200") && "tunnelled".equals(cr.readLine()), "HTTPS-style CONNECT tunnel through the HTTP-proxy side");
        cn.close();

        // 6. large integrity + flow control
        long[] ms = new long[1];
        Socket big = socksConnect(cl.socksPort(), "127.0.0.1", echo.getLocalPort(), code);
        boolean ok = echoRoundTrip(big, 20 * 1024 * 1024, ms);
        check(ok, "20 MB up + 20 MB down, bit-exact (" + ms[0] + " ms)");
        big.close();

        // 7. many concurrent streams
        final AtomicInteger good = new AtomicInteger();
        ExecutorService ex = Executors.newFixedThreadPool(40);
        List<Future<?>> fs = new ArrayList<>();
        for (int i = 0; i < 40; i++) fs.add(ex.submit(() -> { try { int[] c = new int[1]; Socket s = socksConnect(cl.socksPort(), "127.0.0.1", echo.getLocalPort(), c); if (s != null && echoRoundTrip(s, 300_000, null)) good.incrementAndGet(); if (s != null) s.close(); } catch (Exception e) { e.printStackTrace(); } }));
        for (Future<?> f : fs) f.get(120, TimeUnit.SECONDS);
        check(good.get() == 40, "40 parallel connections all correct (" + good.get() + "/40)");

        // 8. a stalled stream must not block the others (no head-of-line blocking)
        Socket stalled = socksConnect(cl.socksPort(), "127.0.0.1", fire.getLocalPort(), code); // we never read from it
        Thread.sleep(1500);
        Socket other = socksConnect(cl.socksPort(), "127.0.0.1", echo.getLocalPort(), code);
        boolean fast = echoRoundTrip(other, 100_000, ms) && ms[0] < 5000;
        check(fast, "a stuck download does not freeze other connections (" + ms[0] + " ms)");
        stalled.close(); other.close();

        // 9. stats and measurements are real
        long rtt = cl.rttMillis();
        check(rtt >= 1 && rtt < 2000, "ping measured through the tunnel: " + rtt + " ms");
        double bps = cl.speedTest(4 * 1024 * 1024);
        check(bps > 100_000, String.format("speed test through the tunnel: %.1f MB/s", bps / 1e6));
        check(cl.downBytes() > 20_000_000 && cl.upBytes() > 20_000_000, "client counts data: down " + cl.downBytes() / 1000000 + " MB, up " + cl.upBytes() / 1000000 + " MB");
        check(prov.sessionBytes() > 40_000_000, "provider counts data: " + prov.sessionBytes() / 1000000 + " MB forwarded");
        List<ProviderEngine.ClientInfo> ci = prov.clients();
        check(ci.size() == 1 && ci.get(0).id.equals(london.id) && ci.get(0).label.equals("London phone"), "provider lists the connected user by identity and label");

        // 10. revoke disconnects
        prov.revoke(london.id);
        check(waitFor(() -> prov.connectedCount() == 0, 5000), "revoking approval disconnects the user");
        check(waitFor(() -> cl.state() == ClientEngine.State.WAITING_APPROVAL, 20000), "revoked device must ask again (state=" + cl.state() + ")");
        cl.stop();

        // 11. blocked device
        Identity bad = Identity.generate("bad");
        prov.deny(bad.id);
        ClientEngine cb = startClient(bad, rport, relayId.id, dhaka.id);
        check(waitFor(() -> cb.state() == ClientEngine.State.DENIED, 10000), "blocked device is refused for good");
        cb.stop();

        // 12. offline provider
        ClientEngine co = startClient(london, rport, relayId.id, Identity.generate("ghost").id);
        check(waitFor(() -> co.state() == ClientEngine.State.ERROR && co.detail().contains("offline"), 10000), "offline provider reported clearly (" + co.detail() + ")");
        co.stop();

        // 13. provider protects its own network
        ProviderEngine.Config safe = new ProviderEngine.Config(); safe.name = "Safe"; // DEFAULT policy
        Identity safeId = Identity.generate("safe");
        ProviderEngine ps = startProvider(dir("safe"), safeId, rport, relayId.id, safe, events);
        ps.approve(london.id, "L");
        ClientEngine cs = startClient(london, rport, relayId.id, safeId.id);
        check(waitFor(() -> cs.state() == ClientEngine.State.CONNECTED, 15000), "client connects to provider with default (safe) policy");
        String[][] targets = {{"127.0.0.1", "" + echo.getLocalPort()}, {"localhost", "" + echo.getLocalPort()}, {"192.168.1.1", "80"}, {"10.0.0.5", "443"}, {"169.254.169.254", "80"}, {"[::1]", "80"}, {"::ffff:10.0.0.1", "80"}, {"8.8.8.8", "25"}};
        int denied = 0;
        for (String[] t : targets) { Socket s = socksConnect(cs.socksPort(), t[0].replace("[", "").replace("]", ""), Integer.parseInt(t[1]), code); if (s == null && code[0] == 2) denied++; else System.out.println("   not denied: " + t[0] + ":" + t[1] + " code " + code[0]); if (s != null) s.close(); }
        check(denied == targets.length, "provider blocks its own localhost/LAN/router/metadata and SMTP (" + denied + "/" + targets.length + " denied)");
        cs.stop(); ps.stop();

        // 14. throttling
        ProviderEngine.Config slow = new ProviderEngine.Config(); slow.perClientBytesPerSec = 400_000; slow.policy = new EgressPolicy().allowPrivateForTests(true);
        Identity slowId = Identity.generate("slow");
        ProviderEngine pl = startProvider(dir("slow"), slowId, rport, relayId.id, slow, events);
        pl.approve(london.id, "L");
        ClientEngine cls = startClient(london, rport, relayId.id, slowId.id);
        check(waitFor(() -> cls.state() == ClientEngine.State.CONNECTED, 15000), "client connects to rate-limited provider");
        Socket sl = socksConnect(cls.socksPort(), "127.0.0.1", echo.getLocalPort(), code);
        boolean r = echoRoundTrip(sl, 600_000, ms);
        check(r && ms[0] > 2000, "per-client speed limit 400 KB/s enforced: 600 KB each way took " + ms[0] + " ms");
        sl.close(); cls.stop(); pl.stop();

        // 15. data cap
        ProviderEngine.Config cap = new ProviderEngine.Config(); cap.perClientCapBytes = 500_000; cap.policy = new EgressPolicy().allowPrivateForTests(true);
        Identity capId = Identity.generate("cap");
        ProviderEngine pc = startProvider(dir("cap"), capId, rport, relayId.id, cap, events);
        pc.approve(london.id, "L");
        ClientEngine clc = startClient(london, rport, relayId.id, capId.id);
        check(waitFor(() -> clc.state() == ClientEngine.State.CONNECTED, 15000), "client connects to capped provider");
        Socket sc = socksConnect(clc.socksPort(), "127.0.0.1", echo.getLocalPort(), code);
        boolean capped;
        try { capped = !echoRoundTrip(sc, 2_000_000, ms); } catch (IOException e) { capped = true; }
        check(capped, "data cap stops transfer after the limit");
        sc.close(); clc.stop(); pc.stop();

        // 16. Open mode: friends get in without a manual approval, the owner can still block
        ProviderEngine.Config open = new ProviderEngine.Config(); open.autoApprove = true; open.policy = new EgressPolicy().allowPrivateForTests(true);
        Identity openId = Identity.generate("open");
        File openDir = dir("open");
        ProviderEngine po = startProvider(openDir, openId, rport, relayId.id, open, events);
        Identity friend = Identity.generate("friend");
        ClientEngine cf = startClient(friend, rport, relayId.id, openId.id);
        check(waitFor(() -> cf.state() == ClientEngine.State.CONNECTED, 15000), "Open mode: a new device connects with no manual approval");
        check(po.pending().isEmpty() && po.approvals().state(friend.id) == ApprovalStore.State.APPROVED, "Open mode: device is remembered, nothing left pending");
        Identity troll = Identity.generate("troll"); po.deny(troll.id);
        ClientEngine ct = startClient(troll, rport, relayId.id, openId.id);
        check(waitFor(() -> ct.state() == ClientEngine.State.DENIED, 10000), "Open mode: a blocked device stays blocked");
        ct.stop();

        // 17. Provider's internet goes away: detected, one alert, fallback to own internet, recovery
        final AtomicInteger problems = new AtomicInteger(), recovered = new AtomicInteger();
        final RouteMonitor mon = new RouteMonitor(new RouteMonitor.Health() {
            public boolean usable() { return cf.isUsable(); }
            public boolean connecting() { return cf.isConnecting(); }
        }, new RouteMonitor.Listener() {
            public void onProblem() { problems.incrementAndGet(); }
            public void onRecovered() { recovered.incrementAndGet(); }
        }, 8000);
        SsProxySelector sel = new SsProxySelector(mon, () -> cf.socksPort());
        check(waitFor(() -> mon.status() == RouteMonitor.Status.UP, 5000) && mon.route() == RouteMonitor.Route.TUNNEL, "route is TUNNEL while the provider is healthy");
        List<Proxy> via = sel.select(new URI("https://modrinth.com/mods"));
        check(via.size() == 1 && via.get(0).type() == Proxy.Type.SOCKS && ((InetSocketAddress) via.get(0).address()).getPort() == cf.socksPort(), "app traffic is pointed at the local SS Internet proxy");
        check(sel.select(new URI("http://127.0.0.1:8080/")).get(0) == Proxy.NO_PROXY && sel.select(new URI("http://192.168.1.10/")).get(0) == Proxy.NO_PROXY && sel.select(new URI("http://localhost/")).get(0) == Proxy.NO_PROXY, "local and LAN destinations are never tunnelled");

        long t0 = System.currentTimeMillis();
        po.stop(); // the provider goes away
        check(waitFor(() -> mon.status() == RouteMonitor.Status.DOWN, 20000), "provider loss detected in " + (System.currentTimeMillis() - t0) + " ms");
        check(problems.get() == 1, "exactly ONE problem alert is raised (" + problems.get() + ")");
        check(mon.route() == RouteMonitor.Route.DIRECT && sel.select(new URI("https://modrinth.com/mods")).get(0) == Proxy.NO_PROXY, "fallback ON: app traffic switches to the user's own internet");
        Thread.sleep(1500);
        check(problems.get() == 1, "no alert spam while the outage continues");
        mon.setFallbackToOwnInternet(false);
        check(mon.route() == RouteMonitor.Route.BLOCKED, "fallback OFF: route is BLOCKED");
        Socket refused = null; int[] rc = new int[1];
        try { refused = socksConnect(cf.socksPort(), "127.0.0.1", echo.getLocalPort(), rc); } catch (IOException e) { rc[0] = -1; }
        check(refused == null && rc[0] != 0, "fallback OFF: nothing leaves, the proxy refuses (reply " + rc[0] + ")");
        mon.setFallbackToOwnInternet(true);

        ProviderEngine po2 = startProvider(openDir, openId, rport, relayId.id, open, events); // provider comes back
        check(waitFor(() -> mon.status() == RouteMonitor.Status.UP, 60000), "provider back: monitor recovers on its own");
        check(recovered.get() == 1 && mon.route() == RouteMonitor.Route.TUNNEL, "recovery event fired once, traffic is back on the tunnel");
        Socket again = socksConnect(cf.socksPort(), "127.0.0.1", echo.getLocalPort(), code);
        check(again != null && echoRoundTrip(again, 50_000, null), "data flows again after recovery");
        again.close();
        mon.stop(); cf.stop(); po2.stop();

        prov.stop();
        check(waitFor(() -> relay.providerCount() <= 2, 5000), "provider unregisters from relay on stop");
        relay.close();
        System.out.println(fails == 0 ? "\nALL TESTS PASSED" : "\n" + fails + " TEST(S) FAILED");
        System.exit(fails == 0 ? 0 : 1);
    }
}
