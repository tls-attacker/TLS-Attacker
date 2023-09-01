/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1Sequence;

public class OcspRequest extends Asn1Sequence {

    private OcspCertId certId;

    private OcspRequestExtensions singleRequestExtensions; // [0]explicit optional

    public OcspRequest(String identifier) {
        super(identifier);
        certId = new OcspCertId("CertID");
        singleRequestExtensions = new OcspRequestExtensions("singleRequestExtensions");
    }

    public OcspCertId getCertId() {
        return certId;
    }

    public void setCertId(OcspCertId certId) {
        this.certId = certId;
    }

    public OcspRequestExtensions getSingleRequestExtensions() {
        return singleRequestExtensions;
    }

    public void setSingleRequestExtensions(OcspRequestExtensions singleRequestExtensions) {
        this.singleRequestExtensions = singleRequestExtensions;
    }
}
