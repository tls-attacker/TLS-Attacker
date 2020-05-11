/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1Sequence;

import java.math.BigInteger;

public class CertificateStatus {

    private Asn1Sequence certificateStatusSequence;
    private String hashAlgorithmIdentifier;
    private byte[] issuerNameHash;
    private byte[] issuerKeyHash;
    private BigInteger serialNumber;
    private int certificateStatus;
    private String timeOfRevocation;
    private String timeOfLastUpdate;
    private String timeOfNextUpdate;

    public Asn1Sequence getCertificateStatusSequence() {
        return certificateStatusSequence;
    }

    public void setCertificateStatusSequence(Asn1Sequence certificateStatusSequence) {
        this.certificateStatusSequence = certificateStatusSequence;
    }

    public String getHashAlgorithmIdentifier() {
        return hashAlgorithmIdentifier;
    }

    public void setHashAlgorithmIdentifier(String hashAlgorithmIdentifier) {
        this.hashAlgorithmIdentifier = hashAlgorithmIdentifier;
    }

    public byte[] getIssuerNameHash() {
        return issuerNameHash;
    }

    public void setIssuerNameHash(byte[] issuerNameHash) {
        this.issuerNameHash = issuerNameHash;
    }

    public byte[] getIssuerKeyHash() {
        return issuerKeyHash;
    }

    public void setIssuerKeyHash(byte[] issuerKeyHash) {
        this.issuerKeyHash = issuerKeyHash;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public int getCertificateStatus() {
        return certificateStatus;
    }

    public void setCertificateStatus(int certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

    public String getTimeOfRevocation() {
        return timeOfRevocation;
    }

    public void setTimeOfRevocation(String timeOfRevocation) {
        this.timeOfRevocation = timeOfRevocation;
    }

    public String getTimeOfLastUpdate() {
        return timeOfLastUpdate;
    }

    public void setTimeOfLastUpdate(String timeOfLastUpdate) {
        this.timeOfLastUpdate = timeOfLastUpdate;
    }

    public String getTimeOfNextUpdate() {
        return timeOfNextUpdate;
    }

    public void setTimeOfNextUpdate(String timeOfNextUpdate) {
        this.timeOfNextUpdate = timeOfNextUpdate;
    }
}
