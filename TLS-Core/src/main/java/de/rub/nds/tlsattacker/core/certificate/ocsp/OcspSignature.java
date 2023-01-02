/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.x509.base.AlgorithmIdentifier;

public class OcspSignature extends Asn1Sequence {

    private AlgorithmIdentifier signatureAlgorithm;

    private Asn1PrimitiveBitString signature;

    private OcspCertificates certs;

    public OcspSignature(String identifier) {
        super(identifier);
        signatureAlgorithm = new AlgorithmIdentifier("signatureAlgorithm");
        signature = new Asn1PrimitiveBitString("signature");
        certs = new OcspCertificates("certs");
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm) {
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
}
