/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class JKSLoader {

    public static org.bouncycastle.asn1.x509.Certificate loadCertificate(KeyStore keyStore, String alias) {
        try {
            if (alias == null || keyStore == null) {
                throw new ConfigurationException("The certificate cannot be fetched. Have you provided correct "
                        + "certificate alias and key? (Current alias: " + alias + ")");
            }
            java.security.cert.Certificate sunCert = keyStore.getCertificate(alias);
            if (sunCert == null) {
                throw new ConfigurationException("The certificate cannot be fetched. Have you provided correct "
                        + "certificate alias and key? (Current alias: " + alias + ")");
            }

            byte[] certBytes = sunCert.getEncoded();

            ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
            org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);
            return cert;
        } catch (KeyStoreException | CertificateEncodingException | IOException ex) {
            throw new ConfigurationException("The certificate cannot be fetched. Have you provided correct "
                    + "certificate alias and key? (Current alias: " + alias + ")");
        }
    }

    public static org.bouncycastle.crypto.tls.Certificate loadTLSCertificate(KeyStore keyStore, String alias) {
        try {
            if (alias == null || keyStore == null) {
                throw new ConfigurationException("The certificate cannot be fetched. Have you provided correct "
                        + "certificate alias and key? (Current alias: " + alias + ")");
            }
            java.security.cert.Certificate sunCert = keyStore.getCertificate(alias);
            if (sunCert == null) {
                throw new ConfigurationException("The certificate cannot be fetched. Have you provided correct "
                        + "certificate alias and key? (Current alias: " + alias + ")");
            }
            byte[] certBytes = sunCert.getEncoded();

            ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
            org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);

            org.bouncycastle.asn1.x509.Certificate[] certs = new org.bouncycastle.asn1.x509.Certificate[1];
            certs[0] = cert;
            org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs);
            return tlsCerts;
        } catch (KeyStoreException | CertificateEncodingException | IOException ex) {
            throw new ConfigurationException("The certificate cannot be fetched. Have you provided correct "
                    + "certificate alias and key? (Current alias: " + alias + ")");
        }

    }

    public static X509CertificateObject loadX509Certificate(KeyStore keyStore, String alias) throws KeyStoreException,
            CertificateEncodingException, IOException, CertificateParsingException {
        return new X509CertificateObject(loadTLSCertificate(keyStore, alias).getCertificateAt(0));
    }

    private JKSLoader() {
    }
}
