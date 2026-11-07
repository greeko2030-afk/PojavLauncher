package com.supersonic.ssinternet.cli;

import com.supersonic.ssinternet.core.ApprovalStore;
import com.supersonic.ssinternet.core.ClientEngine;
import com.supersonic.ssinternet.core.EgressPolicy;
import com.supersonic.ssinternet.core.Identity;
import com.supersonic.ssinternet.core.ProviderEngine;
import com.supersonic.ssinternet.core.RelayLink;
import com.supersonic.ssinternet.core.TlsUtil;
import com.supersonic.ssinternet.relay.RelayServer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/** Windows / Linux / macOS front end: java -jar ssinternet.jar <relay|provider|client|list|id> ... */
public final class SsCli {
    private SsCli() {}

    private static void usage() {
        System.out.println(
                "SS Internet\n\n"
                + "  id        [--dir DIR]                          show this device's ID\n"
                + "  relay     --listen PORT [--dir DIR]            run a relay server (needs a public IP)\n"
                + "            [--keystore FILE.p12 --storepass PW]   use a CA certificate (e.g. Let's Encrypt)\n"
                + "  provider  --relay HOST:PORT [--relay-pin ID]   share this computer's internet\n"
                + "            [--name NAME] [--country BD] [--unlisted] [--open] [--max-clients N]\n"
                + "            [--limit-kbps N] [--cap-mb N] [--dir DIR]\n"
                + "  client    --relay HOST:PORT [--relay-pin ID] --provider ID [--socks PORT] [--dir DIR]\n"
                + "  list      --relay HOST:PORT [--relay-pin ID] [--dir DIR]   show listed providers\n\n"
                + "--open lets new devices in automatically (you can still block/revoke them).\n"
                + "Without --relay-pin the relay's certificate must be valid for its host name (CA signed).\n"
                + "With a self-signed relay, pass the relay ID that 'relay' prints at start.");
    }

    public static void main(String[] argv) throws Exception {
        if (argv.length == 0) { usage(); return; }
        String cmd = argv[0];
        Map<String, String> o = new HashMap<>();
        for (int i = 1; i < argv.length; i++) {
            if (!argv[i].startsWith("--")) { System.err.println("unexpected argument: " + argv[i]); usage(); System.exit(2); }
            String k = argv[i].substring(2);
            if (k.equals("unlisted") || k.equals("open")) o.put(k, "1");
            else if (i + 1 < argv.length) o.put(k, argv[++i]);
            else { System.err.println("missing value for --" + k); System.exit(2); }
        }
        File dir = new File(o.containsKey("dir") ? o.get("dir") : defaultDir());
        switch (cmd) {
            case "id": System.out.println(Identity.pretty(Identity.loadOrCreate(dir, "ss-device").id)); break;
            case "relay": relay(o, dir); break;
            case "provider": provider(o, dir); break;
            case "client": client(o, dir); break;
            case "list": list(o, dir); break;
            default: usage();
        }
    }

    private static String defaultDir() {
        String home = System.getProperty("user.home", ".");
        return new File(home, ".ss-internet").getPath();
    }

    private static String need(Map<String, String> o, String k) {
        String v = o.get(k);
        if (v == null) { System.err.println("--" + k + " is required"); usage(); System.exit(2); }
        return v;
    }

    private static String hostOf(String hp) { int i = hp.lastIndexOf(':'); if (i < 1) { System.err.println("use HOST:PORT"); System.exit(2); } return hp.substring(0, i); }
    private static int portOf(String hp) { return Integer.parseInt(hp.substring(hp.lastIndexOf(':') + 1)); }

    private static void relay(Map<String, String> o, File dir) throws Exception {
        int port = Integer.parseInt(need(o, "listen"));
        SSLContext ctx;
        if (o.containsKey("keystore")) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            char[] pw = need(o, "storepass").toCharArray();
            try (FileInputStream in = new FileInputStream(o.get("keystore"))) { ks.load(in, pw); }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, pw);
            ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), new TrustManager[]{new TlsUtil.AnyClientTrustManager()}, null);
            System.out.println("relay uses the certificate from " + o.get("keystore"));
        } else {
            Identity id = Identity.loadOrCreate(new File(dir, "relay"), "ss-relay");
            ctx = TlsUtil.context(id, new TrustManager[]{new TlsUtil.AnyClientTrustManager()});
            System.out.println("self-signed relay. Give this relay ID to every provider and client (--relay-pin):\n  " + Identity.pretty(id.id));
        }
        RelayServer r = new RelayServer(ctx, port, new RelayServer.Limits());
        System.out.println("relay listening on port " + r.getPort() + " (open this TCP port in the firewall)");
        Thread.currentThread().join();
    }

    private static void list(Map<String, String> o, File dir) throws Exception {
        Identity id = Identity.loadOrCreate(dir, "ss-device");
        String hp = need(o, "relay");
        List<RelayLink.ProviderEntry> l = new RelayLink(hostOf(hp), portOf(hp), o.get("relay-pin"), id).listProviders();
        if (l.isEmpty()) System.out.println("no listed providers online");
        for (RelayLink.ProviderEntry e : l) System.out.println(Identity.pretty(e.id) + "  " + e.name + "  " + e.country + "  users " + e.active + "/" + e.max);
    }

    private static void provider(Map<String, String> o, File dir) throws Exception {
        Identity id = Identity.loadOrCreate(dir, "ss-device");
        String hp = need(o, "relay");
        ProviderEngine.Config c = new ProviderEngine.Config();
        c.name = o.containsKey("name") ? o.get("name") : "SS Internet";
        c.country = o.containsKey("country") ? o.get("country") : "";
        c.listed = !o.containsKey("unlisted");
        c.autoApprove = o.containsKey("open");
        if (o.containsKey("max-clients")) c.maxClients = Integer.parseInt(o.get("max-clients"));
        if (o.containsKey("limit-kbps")) c.perClientBytesPerSec = Long.parseLong(o.get("limit-kbps")) * 1000 / 8;
        if (o.containsKey("cap-mb")) c.totalCapBytes = Long.parseLong(o.get("cap-mb")) * 1_000_000L;
        c.policy = new EgressPolicy();
        final ProviderEngine p = new ProviderEngine(dir, id, hostOf(hp), portOf(hp), o.get("relay-pin"), c, m -> System.out.println("* " + m));
        System.out.println("Your provider ID (share it so people can ask for access):\n  " + Identity.pretty(id.id));
        System.out.println("Commands: pending | approve ID [label] | deny ID | revoke ID | users | stats | quit");
        p.start();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            String[] t = line.trim().split("\\s+", 3);
            try {
                switch (t[0]) {
                    case "pending":
                        for (ApprovalStore.Pending x : p.pending()) System.out.println("  " + Identity.pretty(x.id));
                        break;
                    case "approve": p.approve(t[1], t.length > 2 ? t[2] : ""); System.out.println("approved"); break;
                    case "deny": p.deny(t[1]); System.out.println("blocked"); break;
                    case "revoke": p.revoke(t[1]); System.out.println("revoked"); break;
                    case "users":
                        for (ProviderEngine.ClientInfo x : p.clients())
                            System.out.printf(Locale.US, "  %s %s  down %s  up %s  rtt %d ms  streams %d%n", Identity.pretty(x.id).substring(0, 14), x.label, fmt(x.downBytes), fmt(x.upBytes), x.rttMillis, x.streams);
                        break;
                    case "stats":
                        System.out.printf(Locale.US, "state %s  users %d  speed down %s/s up %s/s  data this run %s  all time %s%n", p.state(), p.connectedCount(), fmt(p.totalDownRate()), fmt(p.totalUpRate()), fmt(p.sessionBytes()), fmt(p.lifetimeBytes()));
                        break;
                    case "quit": p.stop(); return;
                    case "": break;
                    default: System.out.println("unknown command");
                }
            } catch (RuntimeException e) {
                System.out.println("error: " + e.getMessage());
            }
        }
        p.stop();
    }

    private static void client(Map<String, String> o, File dir) throws Exception {
        Identity id = Identity.loadOrCreate(dir, "ss-device");
        String hp = need(o, "relay");
        int socks = o.containsKey("socks") ? Integer.parseInt(o.get("socks")) : 1080;
        final ClientEngine c = new ClientEngine(id, hostOf(hp), portOf(hp), o.get("relay-pin"), need(o, "provider"), socks);
        System.out.println("This device's ID (give it to the provider so they can approve you):\n  " + Identity.pretty(id.id));
        c.start();
        System.out.println("Local SOCKS5 proxy: 127.0.0.1:" + c.socksPort() + "   (type 'speed' for a speed test, 'quit' to stop)");
        Thread t = new Thread(() -> {
            while (true) {
                try { Thread.sleep(5000); } catch (InterruptedException e) { return; }
                System.out.printf(Locale.US, "[%s] %s  ping %d ms  down %s/s up %s/s  data down %s up %s%n", c.state(), c.detail(), c.rttMillis(), fmt(c.downRate()), fmt(c.upRate()), fmt(c.downBytes()), fmt(c.upBytes()));
            }
        });
        t.setDaemon(true);
        t.start();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.trim().equals("quit")) break;
            if (line.trim().equals("speed")) {
                try { System.out.printf(Locale.US, "download through tunnel: %.2f Mbit/s%n", c.speedTest(4 * 1024 * 1024) * 8 / 1e6); }
                catch (Exception e) { System.out.println("speed test failed: " + e.getMessage()); }
            }
        }
        c.stop();
    }

    private static String fmt(long b) {
        if (b < 1000) return b + " B";
        if (b < 1_000_000) return String.format(Locale.US, "%.1f KB", b / 1e3);
        if (b < 1_000_000_000L) return String.format(Locale.US, "%.1f MB", b / 1e6);
        return String.format(Locale.US, "%.2f GB", b / 1e9);
    }
}
