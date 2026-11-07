package com.supersonic.ssinternet.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

/** How a device reaches the relay server: outbound TLS only, so no router or port-forward is ever needed. */
public final class RelayLink {
    public static final class ProviderEntry {
        public final String id, name, country;
        public final int active, max;
        ProviderEntry(String id, String name, String country, int active, int max) {
            this.id = id; this.name = name; this.country = country; this.active = active; this.max = max;
        }
    }

    public final String host;
    public final int port;
    /** If set, the relay must present exactly this identity (self-hosted relay). If null, the system CA store + host name is used. */
    public final String pinId;
    private final Identity identity;
    private final SSLContext ctx;

    public RelayLink(String host, int port, String pinId, Identity identity) throws GeneralSecurityException, IOException {
        this.host = host;
        this.port = port;
        this.pinId = pinId == null || pinId.isEmpty() ? null : Identity.normalizeId(pinId);
        this.identity = identity;
        this.ctx = TlsUtil.context(identity, this.pinId == null ? null : new TrustManager[]{new TlsUtil.PinTrustManager(this.pinId)});
    }

    public SSLSocket connect() throws IOException {
        Socket raw = new Socket();
        try {
            raw.connect(new InetSocketAddress(host, port), 12_000);
            raw.setTcpNoDelay(true);
            raw.setKeepAlive(true);
            SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(raw, host, port, true);
            TlsUtil.harden(s);
            s.setSoTimeout(15_000);
            s.startHandshake();
            if (pinId == null) TlsUtil.verifyHostname(s, host);
            return s;
        } catch (IOException | RuntimeException e) {
            try { raw.close(); } catch (IOException ignored) {}
            throw e;
        }
    }

    /** Sends HELLO and checks the relay's answer. */
    public static void hello(SSLSocket s, String role, String extra) throws IOException {
        OutputStream out = s.getOutputStream();
        LineIO.writeLine(out, "HELLO " + role + " 1" + (extra == null ? "" : " " + extra));
        String r = LineIO.readLine(s.getInputStream(), 256);
        if (!r.startsWith("OK")) throw new IOException("relay refused: " + r);
    }

    /** Asks the relay for the providers that chose to be listed. */
    public List<ProviderEntry> listProviders() throws IOException {
        SSLSocket s = connect();
        try {
            hello(s, "CLIENT", null);
            InputStream in = s.getInputStream();
            LineIO.writeLine(s.getOutputStream(), "LIST");
            List<ProviderEntry> out = new ArrayList<>();
            while (true) {
                String l = LineIO.readLine(in, 512);
                if (l.equals("END")) break;
                String[] p = l.split(" ");
                if (p.length == 6 && p[0].equals("PROVIDER") && Identity.isValidId(p[1])) {
                    try {
                        out.add(new ProviderEntry(p[1], Codec.urlDecode(p[2]), p[3].equals("-") ? "" : p[3], Integer.parseInt(p[4]), Integer.parseInt(p[5])));
                    } catch (NumberFormatException ignored) {}
                }
            }
            LineIO.writeLine(s.getOutputStream(), "BYE");
            return out;
        } finally {
            try { s.close(); } catch (IOException ignored) {}
        }
    }

    Identity identity() { return identity; }
}
