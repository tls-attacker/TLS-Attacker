/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class JKSLoader {

    public static org.bouncycastle.asn1.x509.Certificate loadCertificate(
            KeyStore keyStore, String alias) {
        try {
            if (alias == null || keyStore == null) {
                throw new ConfigurationException(
                        "The certificate cannot be fetched. Have you provided correct "
                                + "certificate alias and key? (Current alias: "
                                + alias
                                + ")");
            }
            Certificate sunCert = keyStore.getCertificate(alias);
            if (sunCert == null) {
                throw new ConfigurationException(
                        "The certificate cannot be fetched. Have you provided correct "
                                + "certificate alias and key? (Current alias: "
                                + alias
                                + ")");
            }

            byte[] certBytes = sunCert.getEncoded();
            return BcTlsCertificate.parseCertificate(certBytes);
        } catch (KeyStoreException | CertificateEncodingException | IOException ex) {
            throw new ConfigurationException(
                    "The certificate cannot be fetched. Have you provided correct "
                            + "certificate alias and key? (Current alias: "
                            + alias
                            + ")");
        }
    }

    public static TlsCertificate loadTLSCertificate(KeyStore keyStore, String alias) {
        return new BcTlsCertificate(new BcTlsCrypto(), loadCertificate(keyStore, alias));
    }

    private JKSLoader() {}
}
