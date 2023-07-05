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
import de.rub.nds.tlsattacker.core.certificate.CrlReason;
import de.rub.nds.tlsattacker.core.certificate.ObjectIdentifierTranslator;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import org.bouncycastle.util.encoders.Hex;

public class CertificateStatus {

    private Asn1Sequence certificateStatusSequence;
    private String hashAlgorithmIdentifier;
    private byte[] issuerNameHash;
    private byte[] issuerKeyHash;
    private BigInteger serialNumber;
    private Integer certificateStatus;
    private String revocationTime;
    private Integer revocationReason;
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

    public Integer getCertificateStatus() {
        return certificateStatus;
    }

    public void setCertificateStatus(Integer certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

    public String getRevocationTime() {
        return revocationTime;
    }

    public void setRevocationTime(String revocationTime) {
        this.revocationTime = revocationTime;
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

    public Integer getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(Integer revocationReason) {
        this.revocationReason = revocationReason;
    }

    private String formatDate(String unformattedDateString) {
        DateTimeFormatter inputFormatter =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'", Locale.ENGLISH);
        DateTimeFormatter outputFormatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
        LocalDateTime date = LocalDateTime.parse(unformattedDateString, inputFormatter);
        return outputFormatter.format(date);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Certificate Status");
        // Use status value to determine if object has been filled
        if (certificateStatus != null) {
            sb.append("\n Hash Algorithm: ")
                    .append(ObjectIdentifierTranslator.translate(getHashAlgorithmIdentifier()));
            sb.append("\n Issuer Name Hash: 0x").append(Hex.toHexString(getIssuerNameHash()));
            sb.append("\n Issuer Key Hash: 0x").append(Hex.toHexString(getIssuerKeyHash()));
            sb.append("\n Serial Number: 0x").append(getSerialNumber().toString(16));
            sb.append("\n Certificate Status: ");
            sb.append(RevocationStatus.translate(getCertificateStatus()));
            if (getCertificateStatus().equals(RevocationStatus.translate("revoked"))) {
                sb.append("\n Revocation Time: ").append(formatDate(getRevocationTime()));
                if (getRevocationReason() != null) {
                    sb.append("\n Revocation Reason: ");
                    sb.append(CrlReason.translate(getRevocationReason()));
                }
            }
            sb.append("\n Last Update: ").append(formatDate(getTimeOfLastUpdate()));
            sb.append("\n Next Update: ").append(formatDate(getTimeOfNextUpdate()));
        }
        return sb.toString();
    }
}
