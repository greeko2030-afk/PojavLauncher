package com.supersonic.ssinternet.core;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

/**
 * Device identity: an EC P-256 key pair with a self-signed certificate.
 * The device ID is the base32 SHA-256 of the certificate, so an ID can not be faked
 * without owning the private key (same idea as SSH host keys or Syncthing device IDs).
 */
public final class Identity {
    public final PrivateKey key;
    public final X509Certificate cert;
    public final byte[] certDer;
    /** 52 characters, base32, no dashes. */
    public final String id;

    private Identity(PrivateKey key, X509Certificate cert, byte[] certDer) {
        this.key = key;
        this.cert = cert;
        this.certDer = certDer;
        this.id = fingerprintId(certDer);
    }

    public static String fingerprintId(byte[] certDer) {
        try {
            return Codec.base32(MessageDigest.getInstance("SHA-256").digest(certDer));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Returns the canonical upper-case ID without separators, or throws if it is not a valid ID. */
    public static String normalizeId(String text) {
        if (text == null) throw new IllegalArgumentException("empty ID");
        String s = text.replace("-", "").replace(" ", "").trim().toUpperCase(java.util.Locale.US);
        if (s.length() != 52 || !Codec.isBase32(s)) throw new IllegalArgumentException("not a valid device ID");
        return s;
    }

    public static boolean isValidId(String text) {
        try {
            normalizeId(text);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** XXXX-XXXX-... for display. */
    public static String pretty(String id) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < id.length(); i += 4) {
            if (i > 0) sb.append('-');
            sb.append(id, i, Math.min(id.length(), i + 4));
        }
        return sb.toString();
    }

    public static Identity generate(String commonName) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        byte[] sigAlg = Der.seq(Der.oid("1.2.840.10045.4.3.2")); // ecdsa-with-SHA256
        byte[] name = Der.seq(Der.set(Der.seq(Der.oid("2.5.4.3"), Der.utf8(commonName))));
        long now = System.currentTimeMillis();
        byte[] validity = Der.seq(
                Der.utcTime(new Date(now - 24L * 3600 * 1000)),
                Der.utcTime(new Date(now + 20L * 365 * 24 * 3600 * 1000)));
        byte[] serial = new byte[16];
        new SecureRandom().nextBytes(serial);
        serial[0] &= 0x7f;
        byte[] tbs = Der.seq(
                Der.tlv(0xA0, Der.integer(BigInteger.valueOf(2))),
                Der.integer(new BigInteger(1, serial)),
                sigAlg,
                name,
                validity,
                name,
                kp.getPublic().getEncoded());
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(kp.getPrivate());
        sig.update(tbs);
        byte[] der = Der.seq(tbs, sigAlg, Der.bitString(sig.sign()));
        X509Certificate cert = parse(der);
        return new Identity(kp.getPrivate(), cert, der);
    }

    private static X509Certificate parse(byte[] der) throws GeneralSecurityException {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    /** Loads identity.key + identity.crt from dir, creating them the first time. */
    public static synchronized Identity loadOrCreate(File dir, String commonName) throws IOException, GeneralSecurityException {
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IOException("cannot create " + dir);
        File keyFile = new File(dir, "identity.key");
        File crtFile = new File(dir, "identity.crt");
        if (keyFile.isFile() && crtFile.isFile()) {
            byte[] keyBytes = readAll(keyFile);
            byte[] crtBytes = readAll(crtFile);
            PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            return new Identity(key, parse(crtBytes), crtBytes);
        }
        Identity id = generate(commonName);
        writeSecret(keyFile, id.key.getEncoded());
        writeSecret(crtFile, id.certDer);
        return id;
    }

    private static byte[] readAll(File f) throws IOException {
        FileInputStream in = new FileInputStream(f);
        try {
            byte[] buf = new byte[(int) f.length()];
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n < 0) throw new IOException("short read: " + f);
                off += n;
            }
            return buf;
        } finally {
            in.close();
        }
    }

    private static void writeSecret(File f, byte[] data) throws IOException {
        File tmp = new File(f.getPath() + ".tmp");
        FileOutputStream out = new FileOutputStream(tmp);
        try {
            out.write(data);
            out.getFD().sync();
        } finally {
            out.close();
        }
        // owner-only, best effort (no-op on Windows; Android app storage is already private)
        tmp.setReadable(false, false);
        tmp.setReadable(true, true);
        tmp.setWritable(false, false);
        tmp.setWritable(true, true);
        if (!tmp.renameTo(f)) throw new IOException("cannot write " + f);
    }
}
