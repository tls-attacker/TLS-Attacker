/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.certificate;

import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.TlsUtils;

/**
 *
 * @author ic0ns
 */
public class CertificateAdapter extends XmlAdapter<String, Certificate> {

    @Override
    public Certificate unmarshal(String v) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> certs = certFactory.generateCertificates(new ByteArrayInputStream(ArrayConverter.hexStringToByteArray(v.replaceAll("\\s+",""))));
        java.security.cert.Certificate sunCert = (java.security.cert.Certificate) certs.toArray()[0];
        byte[] certBytes = sunCert.getEncoded();
        ASN1Primitive asn1Cert = TlsUtils.readDERObject(certBytes);
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate
                .getInstance(asn1Cert);
        return cert;
    }

    @Override
    public String marshal(Certificate v) throws Exception {
        return ArrayConverter.bytesToHexString(v.getEncoded());
    }

}
