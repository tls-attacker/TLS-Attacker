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
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 *
 * @author robert
 */
public class PemUtil {

    public static Certificate readCertificate(File f) throws FileNotFoundException, CertificateException, IOException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> certs = certFactory
                .generateCertificates(new FileInputStream(f));
        java.security.cert.Certificate sunCert = (java.security.cert.Certificate) certs.toArray()[0];
        byte[] certBytes = sunCert.getEncoded();
        ASN1Primitive asn1Cert = TlsUtils.readASN1Object(certBytes);
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);
        org.bouncycastle.asn1.x509.Certificate[] certs2 = new org.bouncycastle.asn1.x509.Certificate[1];
        certs2[0] = cert;
        org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs2);
        return tlsCerts;
    }

    public static PrivateKey readPrivateKey(File f) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(f);
        InputStreamReader reader = new InputStreamReader(fileInputStream);
        PEMParser parser = null;
        try {
            parser = new PEMParser(reader);
            Object obj = parser.readObject();
            if (obj instanceof PEMKeyPair) {
                PEMKeyPair pair = (PEMKeyPair) obj;
                obj = pair.getPrivateKeyInfo();
            }
            PrivateKeyInfo privKeyInfo = (PrivateKeyInfo) obj;
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPrivateKey(privKeyInfo);
        } finally {
            if (parser != null) {
                parser.close();
            }
            fileInputStream.close();
            reader.close();
        }
    }
    
    

    public static byte[] encodeCert(Certificate cert) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        cert.encode(stream);
        return stream.toByteArray();
    }
}
