/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.tlsattacker.core.certificate.ObjectIdentifierTranslator;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class CertificateStatus {

    private Asn1Sequence certificateStatusSequence;
    private String hashAlgorithmIdentifier;
    private byte[] issuerNameHash;
    private byte[] issuerKeyHash;
    private BigInteger serialNumber;
    private Integer certificateStatus;
    private String timeOfRevocation;
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

    public Integer getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(Integer revocationReason) {
        this.revocationReason = revocationReason;
    }

    private String formatDate(String unformattedDateString) {
        DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'", Locale.ENGLISH);
        DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
        LocalDateTime date = LocalDateTime.parse(unformattedDateString, inputFormatter);
        return outputFormatter.format(date);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Certificate Status");
        // Use status value to determine if object has been filled
        if (certificateStatus != null) {
            sb.append("\n Hash Algorithm: ").append(ObjectIdentifierTranslator.translate(getHashAlgorithmIdentifier()));
            sb.append("\n Issuer Name Hash: ").append(Hex.toHexString(getIssuerNameHash()));
            sb.append("\n Issuer Key Hash: ").append(Hex.toHexString(getIssuerKeyHash()));
            sb.append("\n Serial Number: ").append(getSerialNumber().toString(16));
            sb.append("\n Certificate Status: ");
            if (getCertificateStatus() == 0) {
                sb.append("good");
            } else if (getCertificateStatus() == 1) {
                sb.append("revoked");
                sb.append("\n Time of Revocation: ").append(formatDate(getTimeOfRevocation()));
                if (getRevocationReason() != null) {
                    sb.append("\n Revocation Reason: ");
                    switch (getRevocationReason()) {
                        case 0:
                            sb.append("unspecified");
                            break;
                        case 1:
                            sb.append("keyCompromise");
                            break;
                        case 2:
                            sb.append("cACompromise");
                            break;
                        case 3:
                            sb.append("affiliationChanged");
                            break;
                        case 4:
                            sb.append("superseded");
                            break;
                        case 5:
                            sb.append("cessationOfOperation");
                            break;
                        case 6:
                            sb.append("certificateHold");
                            break;
                        // case 7 is undefined by standard
                        case 8:
                            sb.append("removeFromCRL");
                            break;
                        case 9:
                            sb.append("privilegeWithdrawn");
                            break;
                        case 10:
                            sb.append("aACompromise");
                            break;
                    }
                }
            } else if (getCertificateStatus() == 2) {
                sb.append("unknown");
            }
            sb.append("\n Last Update: ").append(formatDate(getTimeOfLastUpdate()));
            sb.append("\n Next Update: ").append(formatDate(getTimeOfNextUpdate()));
        }
        return sb.toString();
    }
}
