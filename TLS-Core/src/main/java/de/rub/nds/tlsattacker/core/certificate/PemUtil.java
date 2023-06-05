/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import org.apache.logging.log4j.LogManager;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class PemUtil {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger();

    private static final String PRIVATE_KEY = "PRIVATE KEY";

    private static final String PUBLIC_KEY = "PUBLIC KEY";

    public static void writePrivateKey(PrivateKey key, File targetFile) {
        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            writePrivateKey(key, fos);
        } catch (IOException ex) {
            LOGGER.warn(ex);
        }
    }

    public static void writePrivateKey(PrivateKey key, OutputStream outputStream) {
        writePrivateKey(key.getEncoded(), outputStream);
    }

    public static void writePrivateKey(byte[] encodedKey, OutputStream outputStream) {
        writeKey(PRIVATE_KEY, encodedKey, outputStream);
    }

    public static void writePublicKey(PublicKey key, File targetFile) {
        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            writePublicKey(key, fos);
        } catch (IOException ex) {
            LOGGER.warn(ex);
        }
    }

    public static void writePublicKey(PublicKey key, OutputStream outputStream) {
        writePublicKey(key.getEncoded(), outputStream);
    }

    public static void writePublicKey(byte[] encodedKey, OutputStream outputStream) {
        writeKey(PUBLIC_KEY, encodedKey, outputStream);
    }

    private static void writeKey(String keyType, byte[] encodedKey, OutputStream outputStream) {
        PemObject pemObject = new PemObject(keyType, encodedKey);
        try (OutputStreamWriter writer = new OutputStreamWriter(outputStream);
                PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(pemObject);
        } catch (IOException ex) {
            LOGGER.warn(ex);
        }
    }

    public static void writeCertificate(Certificate cert, File file) {
        try (FileWriter writer = new FileWriter(file);
                PemWriter pemWriter = new PemWriter(writer)) {
            for (org.bouncycastle.asn1.x509.Certificate tempCert : cert.getCertificateList()) {
                PemObject pemObject = new PemObject("CERTIFICATE", tempCert.getEncoded());
                pemWriter.writeObject(pemObject);
            }
        } catch (IOException ex) {
            LOGGER.warn(ex);
        }
    }

    public static Certificate readCertificate(InputStream stream)
            throws CertificateException, IOException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> certs =
                certFactory.generateCertificates(stream);
        java.security.cert.Certificate sunCert =
                (java.security.cert.Certificate) certs.toArray()[0];
        byte[] certBytes = sunCert.getEncoded();
        ASN1Primitive asn1Cert = TlsUtils.readASN1Object(certBytes);
        org.bouncycastle.asn1.x509.Certificate cert =
                org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);
        org.bouncycastle.asn1.x509.Certificate[] certs2 =
                new org.bouncycastle.asn1.x509.Certificate[1];
        certs2[0] = cert;
        org.bouncycastle.crypto.tls.Certificate tlsCerts =
                new org.bouncycastle.crypto.tls.Certificate(certs2);
        return tlsCerts;
    }

    public static Certificate readCertificate(File f) throws CertificateException, IOException {
        try (FileInputStream fis = new FileInputStream(f)) {
            return readCertificate(fis);
        }
    }

    public static PrivateKey readPrivateKey(InputStream stream) throws IOException {
        try (InputStreamReader reader = new InputStreamReader(stream);
                PEMParser parser = new PEMParser(reader)) {
            Object obj = parser.readObject();
            if (obj instanceof PEMKeyPair) {
                PEMKeyPair pair = (PEMKeyPair) obj;
                obj = pair.getPrivateKeyInfo();
            } else if (obj instanceof ASN1ObjectIdentifier) {
                obj = parser.readObject();
                PEMKeyPair pair = (PEMKeyPair) obj;
                obj = pair.getPrivateKeyInfo();
            }
            PrivateKeyInfo privKeyInfo = (PrivateKeyInfo) obj;
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPrivateKey(privKeyInfo);
        } catch (Exception e) {
            throw new IOException("Could not read private key", e);
        }
    }

    public static PrivateKey readPrivateKey(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f)) {
            return readPrivateKey(fis);
        }
    }

    public static PublicKey readPublicKey(InputStream stream) throws IOException {
        try (InputStreamReader reader = new InputStreamReader(stream);
                PEMParser parser = new PEMParser(reader)) {
            Object obj = parser.readObject();
            if (obj instanceof PEMKeyPair) {
                PEMKeyPair pair = (PEMKeyPair) obj;
                obj = pair.getPublicKeyInfo();
            }
            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) obj;
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPublicKey(publicKeyInfo);
        } catch (Exception e) {
            throw new IOException("Could not read public key", e);
        }
    }

    public static PublicKey readPublicKey(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f)) {
            return readPublicKey(fis);
        }
    }

    public static byte[] encodeCert(Certificate cert) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        cert.encode(stream);
        return stream.toByteArray();
    }

    private PemUtil() {}
}
