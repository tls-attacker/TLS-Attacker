/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.handler.EmptyHandler;
import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.*;

public class OcspRequestMessage extends Asn1Sequence<OcspChooser> {

    private OcspTbsRequest tbsRequest;
    private OcspSignature optinalSignature;

    public OcspRequestMessage() {
        super("OCSPRequest");
        tbsRequest = new OcspTbsRequest("TBSRequest");
        optinalSignature = new OcspSignature("optinalSignature");
        addChild(tbsRequest);
        addChild(optinalSignature);
    }

    public OcspTbsRequest getTbsRequest() {
        return tbsRequest;
    }

    public void setTbsRequest(OcspTbsRequest tbsRequest) {
        this.tbsRequest = tbsRequest;
    }

    public OcspSignature getOptinalSignature() {
        return optinalSignature;
    }

    public void setOptinalSignature(OcspSignature optinalSignature) {
        this.optinalSignature = optinalSignature;
    }

    @Override
    public Handler getHandler(OcspChooser chooser) {
        return new EmptyHandler(chooser);
    }
}
