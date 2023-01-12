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
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;

public class OcspSignature extends Asn1Sequence<OcspChooser> {

    private OcspSignatureAlgorithmIdentifier signatureAlgorithm;

    private Asn1PrimitiveBitString signature;

    private OcspCertificates certs;

    public OcspSignature(String identifier) {
        super(identifier);
        signatureAlgorithm = new OcspSignatureAlgorithmIdentifier("signatureAlgorithm");
        signature = new Asn1PrimitiveBitString("signature");
        certs = new OcspCertificates("certs");
    }

    public OcspSignatureAlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(OcspSignatureAlgorithmIdentifier signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public Asn1PrimitiveBitString getSignature() {
        return signature;
    }

    public void setSignature(Asn1PrimitiveBitString signature) {
        this.signature = signature;
    }

    public OcspCertificates getCerts() {
        return certs;
    }

    public void setCerts(OcspCertificates certs) {
        this.certs = certs;
    }

    @Override
    public Handler getHandler(OcspChooser chooser) {
        return new EmptyHandler(chooser);
    }
}
