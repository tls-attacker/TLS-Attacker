/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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

    public static void writePublicKey(PublicKey key, File targetFile) {
        PemObject pemObject = new PemObject("PublicKey", key.getEncoded());
        PemWriter pemWriter = null;
        try {
            pemWriter = new PemWriter(new FileWriter(targetFile));
            pemWriter.writeObject(pemObject);
        } catch (IOException ex) {
            LOGGER.warn(ex);
        } finally {
            try {
                pemWriter.close();
            } catch (IOException ex) {
                LOGGER.warn(ex);
            }
        }
    }

    public static void writeCertificate(Certificate cert, File file) {

        PemWriter pemWriter = null;
        try {
            pemWriter = new PemWriter(new FileWriter(file));
            for (org.bouncycastle.asn1.x509.Certificate tempCert : cert.getCertificateList()) {
                PemObject pemObject = new PemObject("CERTIFICATE", tempCert.getEncoded());
                pemWriter.writeObject(pemObject);
            }
            pemWriter.flush();
        } catch (IOException ex) {
            LOGGER.warn(ex);
        } finally {
            try {
                pemWriter.close();
            } catch (IOException ex) {
                LOGGER.warn(ex);
            }
        }
    }

    public static Certificate readCertificate(InputStream stream) throws FileNotFoundException, CertificateException,
            IOException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> certs = certFactory.generateCertificates(stream);
        java.security.cert.Certificate sunCert = (java.security.cert.Certificate) certs.toArray()[0];
        byte[] certBytes = sunCert.getEncoded();
        ASN1Primitive asn1Cert = TlsUtils.readASN1Object(certBytes);
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);
        org.bouncycastle.asn1.x509.Certificate[] certs2 = new org.bouncycastle.asn1.x509.Certificate[1];
        certs2[0] = cert;
        org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs2);
        return tlsCerts;
    }

    public static Certificate readCertificate(File f) throws FileNotFoundException, CertificateException, IOException {
        return readCertificate(new FileInputStream(f));
    }

    public static PrivateKey readPrivateKey(InputStream stream) throws IOException {
        InputStreamReader reader = new InputStreamReader(stream);
        try (PEMParser parser = new PEMParser(reader)) {
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
        } catch (Exception E) {
            throw new IOException("Could not read private key", E);
        } finally {
            stream.close();
            reader.close();
        }
    }

    public static PrivateKey readPrivateKey(File f) throws IOException {
        return readPrivateKey(new FileInputStream(f));
    }

    public static PublicKey readPublicKey(InputStream stream) throws IOException {
        InputStreamReader reader = new InputStreamReader(stream);
        try (PEMParser parser = new PEMParser(reader)) {
            Object obj = parser.readObject();
            if (obj instanceof PEMKeyPair) {
                PEMKeyPair pair = (PEMKeyPair) obj;
                obj = pair.getPublicKeyInfo();
            }
            SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) obj;
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPublicKey(publicKeyInfo);
        } catch (Exception E) {
            throw new IOException("Could not read public key", E);
        } finally {
            stream.close();
            reader.close();
        }
    }

    public static PublicKey readPublicKey(File f) throws IOException {
        return readPublicKey(new FileInputStream(f));
    }

    public static byte[] encodeCert(Certificate cert) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        cert.encode(stream);
        return stream.toByteArray();
    }

    private PemUtil() {
    }
}
