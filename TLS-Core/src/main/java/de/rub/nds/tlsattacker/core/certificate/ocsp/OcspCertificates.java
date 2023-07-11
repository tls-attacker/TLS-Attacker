/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.List;

public class OcspCertificates extends Asn1Sequence {

    private List<X509Certificate> certificateList;

    public OcspCertificates(String identifier) {
        super(identifier);
    }

    public List<X509Certificate> getCertificateList() {
        return certificateList;
    }

    public void setCertificateList(List<X509Certificate> certificateList) {
        this.certificateList = certificateList;
    }
}
