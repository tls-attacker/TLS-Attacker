/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class X509CertificateObjectAdapter extends XmlAdapter<String, X509CertificateObject> {

    @Override
    public X509CertificateObject unmarshal(String v) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> certs = certFactory
                .generateCertificates(new ByteArrayInputStream(ArrayConverter.hexStringToByteArray(v.replaceAll("\\s+",
                        ""))));
        java.security.cert.Certificate sunCert = (java.security.cert.Certificate) certs.toArray()[0];
        byte[] certBytes = sunCert.getEncoded();
        ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert);
        org.bouncycastle.asn1.x509.Certificate[] certs2 = new org.bouncycastle.asn1.x509.Certificate[1];
        certs2[0] = cert;
        org.bouncycastle.crypto.tls.Certificate tlsCerts = new org.bouncycastle.crypto.tls.Certificate(certs2);

        X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));
        return x509CertObject;
    }

    @Override
    public String marshal(X509CertificateObject v) throws Exception {
        return ArrayConverter.bytesToHexString(v.getEncoded());
    }

}
