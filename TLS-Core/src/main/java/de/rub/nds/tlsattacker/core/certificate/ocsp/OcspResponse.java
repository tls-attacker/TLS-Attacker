/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1Enumerated;
import de.rub.nds.asn1.model.Asn1Sequence;

public class OcspResponse extends Asn1Sequence {

    private Asn1Enumerated responseStatus;

    private OcspResponseBytes responseBytes;

    public OcspResponse(String identifier) {
        super(identifier);
    }

    public Asn1Enumerated getResponseStatus() {
        return responseStatus;
    }

    public void setResponseStatus(Asn1Enumerated responseStatus) {
        this.responseStatus = responseStatus;
    }

    public OcspResponseBytes getResponseBytes() {
        return responseBytes;
    }

    public void setResponseBytes(OcspResponseBytes responseBytes) {
        this.responseBytes = responseBytes;
    }
}
