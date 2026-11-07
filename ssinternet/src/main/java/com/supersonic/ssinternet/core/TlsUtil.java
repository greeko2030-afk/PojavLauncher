package com.supersonic.ssinternet.core;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public final class TlsUtil {
    private TlsUtil() {}

    /** Context that presents our identity as the (client or server) certificate. tms == null means system trust store. */
    public static SSLContext context(Identity id, TrustManager[] tms) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("device", id.key, new char[0], new Certificate[]{id.cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tms, new SecureRandom());
        return ctx;
    }

    /** Only TLS 1.2 and 1.3, whichever the platform has. */
    public static void harden(SSLSocket s) {
        List<String> ok = new ArrayList<>();
        for (String p : s.getSupportedProtocols()) {
            if (p.equals("TLSv1.3") || p.equals("TLSv1.2")) ok.add(p);
        }
        if (ok.isEmpty()) throw new IllegalStateException("platform has no TLS 1.2/1.3");
        s.setEnabledProtocols(ok.toArray(new String[0]));
    }

    public static String peerId(SSLSocket s) throws SSLPeerUnverifiedException {
        Certificate[] chain = s.getSession().getPeerCertificates();
        if (chain == null || chain.length == 0) throw new SSLPeerUnverifiedException("no peer certificate");
        try {
            return Identity.fingerprintId(chain[0].getEncoded());
        } catch (CertificateException e) {
            throw new SSLPeerUnverifiedException(e.getMessage());
        }
    }

    public static void verifyHostname(SSLSocket s, String host) throws IOException {
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, s.getSession())) {
            throw new IOException("relay certificate does not match host name " + host);
        }
    }

    /** Accepts exactly one certificate: the one whose fingerprint is the expected device ID. */
    public static final class PinTrustManager implements X509TrustManager {
        private final byte[] expected;

        public PinTrustManager(String expectedId) {
            this.expected = expectedId.getBytes(java.nio.charset.Charset.forName("US-ASCII"));
        }

        private void check(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("empty chain");
            String got = Identity.fingerprintId(chain[0].getEncoded());
            if (!MessageDigest.isEqual(got.getBytes(java.nio.charset.Charset.forName("US-ASCII")), expected)) {
                throw new CertificateException("peer identity does not match the expected device ID");
            }
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException { check(chain); }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { check(chain); }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    /**
     * Server side: lets any device present a certificate. Who the device is gets decided afterwards
     * from its certificate fingerprint (approval list), not by a certificate authority.
     */
    public static final class AnyClientTrustManager implements X509TrustManager {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("client certificate required");
        }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("not a client trust manager");
        }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static boolean arrayEquals(byte[] a, byte[] b) { return Arrays.equals(a, b); }
}
