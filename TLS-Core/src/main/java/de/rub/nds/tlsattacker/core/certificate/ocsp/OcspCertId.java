/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.x509.base.AlgorithmIdentifier;

public class OcspCertId extends Asn1Sequence {

    private AlgorithmIdentifier algorithmIdentifier;
    private Asn1PrimitiveOctetString issuerNameHash;
    private Asn1PrimitiveOctetString issuerKeyHash;
    private Asn1Integer serialNumber;

    public OcspCertId(String identifier) {
        super(identifier);
        algorithmIdentifier = new AlgorithmIdentifier("hashAlgorithm");
        issuerNameHash = new Asn1PrimitiveOctetString("issuerNameHash");
        issuerKeyHash = new Asn1PrimitiveOctetString("issuerKeyHash");
        serialNumber = new Asn1Integer("serialNumber");
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public void setAlgorithmIdentifier(AlgorithmIdentifier algorithmIdentifier) {
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public Asn1PrimitiveOctetString getIssuerNameHash() {
        return issuerNameHash;
    }

    public void setIssuerNameHash(Asn1PrimitiveOctetString issuerNameHash) {
        this.issuerNameHash = issuerNameHash;
    }

    public Asn1PrimitiveOctetString getIssuerKeyHash() {
        return issuerKeyHash;
    }

    public void setIssuerKeyHash(Asn1PrimitiveOctetString issuerKeyHash) {
        this.issuerKeyHash = issuerKeyHash;
    }

    public Asn1Integer getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(Asn1Integer serialNumber) {
        this.serialNumber = serialNumber;
    }
}
