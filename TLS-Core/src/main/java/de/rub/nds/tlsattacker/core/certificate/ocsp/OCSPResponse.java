/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.BASIC;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.certificate.CrlReason;
import de.rub.nds.tlsattacker.core.certificate.ObjectIdentifierTranslator;
import java.io.IOException;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.util.encoders.Hex;

public class OCSPResponse {
    private List<CertificateStatus> certificateStatusList = new LinkedList<>();
    private byte[] encodedResponse;
    private byte[] responderKey;
    private Integer responseStatus;
    private Integer responseDataVersion;
    private BigInteger nonce;
    private String producedAt;
    private String responseTypeIdentifier;
    private String signatureAlgorithmIdentifier;
    private byte[] signature;
    private List<Asn1Encodable> responderName;
    private Certificate certificate;

    public List<CertificateStatus> getCertificateStatusList() {
        return certificateStatusList;
    }

    public void setCertificateStatusList(List<CertificateStatus> certificateStatusList) {
        this.certificateStatusList = certificateStatusList;
    }

    public byte[] getEncodedResponse() {
        return encodedResponse;
    }

    public void setEncodedResponse(byte[] encodedResponse) {
        this.encodedResponse = encodedResponse;
    }

    public byte[] getResponderKey() {
        return responderKey;
    }

    public void setResponderKey(byte[] responderKey) {
        this.responderKey = responderKey;
    }

    public Integer getResponseStatus() {
        return responseStatus;
    }

    public void setResponseStatus(Integer responseStatus) {
        this.responseStatus = responseStatus;
    }

    public Integer getResponseDataVersion() {
        return responseDataVersion;
    }

    public void setResponseDataVersion(Integer responseDataVersion) {
        this.responseDataVersion = responseDataVersion;
    }

    public String getProducedAt() {
        return producedAt;
    }

    public void setProducedAt(String producedAt) {
        this.producedAt = producedAt;
    }

    public String getResponseTypeIdentifier() {
        return responseTypeIdentifier;
    }

    public void setResponseTypeIdentifier(String responseTypeIdentifier) {
        this.responseTypeIdentifier = responseTypeIdentifier;
    }

    public String getSignatureAlgorithmIdentifier() {
        return signatureAlgorithmIdentifier;
    }

    public void setSignatureAlgorithmIdentifier(String signatureAlgorithmIdentifier) {
        this.signatureAlgorithmIdentifier = signatureAlgorithmIdentifier;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public List<Asn1Encodable> getResponderName() {
        return responderName;
    }

    public void setResponderName(List<Asn1Encodable> responderName) {
        this.responderName = responderName;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public void setNonce(BigInteger nonce) {
        this.nonce = nonce;
    }

    private String formatDate(String unformattedDateString) {
        DateTimeFormatter inputFormatter =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'", Locale.ENGLISH);
        DateTimeFormatter outputFormatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
        LocalDateTime date = LocalDateTime.parse(unformattedDateString, inputFormatter);
        return outputFormatter.format(date);
    }

    private String parseResponderName() {
        StringBuilder sb = new StringBuilder();
        for (Asn1Encodable enc : responderName) {
            if (enc instanceof Asn1Set) {
                Asn1Sequence sequence = (Asn1Sequence) ((Asn1Set) enc).getChildren().get(0);
                List<Asn1Encodable> dnKeyValue = sequence.getChildren();
                String oid = ((Asn1ObjectIdentifier) dnKeyValue.get(0)).getValue();
                String value = "";
                if (dnKeyValue.get(1) instanceof Asn1PrimitivePrintableString) {
                    value = ((Asn1PrimitivePrintableString) dnKeyValue.get(1)).getValue();
                } else if (dnKeyValue.get(1) instanceof Asn1PrimitiveUtf8String) {
                    value = ((Asn1PrimitiveUtf8String) dnKeyValue.get(1)).getValue();
                }
                sb.append("\n   ")
                        .append(ObjectIdentifierTranslator.translate(oid))
                        .append(": ")
                        .append(value);
            }
        }
        return sb.toString();
    }

    private byte[] getResponseCertificateBytes() throws IOException {
        org.bouncycastle.asn1.x509.Certificate certificate = this.certificate.getCertificateAt(0);
        return certificate.getEncoded();
    }

    public String toString() {
        return toString(true);
    }

    public String toString(boolean includeSignatureAndCertificate) {
        StringBuilder sb = new StringBuilder();
        sb.append("OCSP Response:");

        // If response was not successful or object was empty...
        if (getResponseStatus() != null && getResponseStatus() > 0) {
            sb.append(OCSPResponseStatus.translate(getResponseStatus()));
            return sb.toString();
        }

        sb.append("\n Version: ");
        if (getResponseDataVersion() == null || getResponseDataVersion() == 0) {
            sb.append("1 (0x0)");
        } else {
            sb.append("0x").append(Integer.toHexString(getResponseDataVersion()));
        }
        sb.append("\n Produced at: ").append(formatDate(getProducedAt()));
        sb.append("\n Response Type: ");
        if (getResponseTypeIdentifier().equals(BASIC.getOID())) {
            sb.append("OCSP Basic Response");
        } else {
            sb.append(getResponseTypeIdentifier());
        }
        if (getResponderName() != null) {
            sb.append("\n Responder DN: ").append(parseResponderName());
        } else if (getResponderKey() != null) {
            sb.append("\n Responder ID: ").append("0x").append(Hex.toHexString(getResponderKey()));
        }
        if (getNonce() != null) {
            sb.append("\n Nonce: ").append(getNonce().toString());
        }

        int certificateCounter = 0;

        for (CertificateStatus certificateStatus : getCertificateStatusList()) {
            certificateCounter++;
            sb.append("\n Certificate Status No. ").append(certificateCounter);
            sb.append("\n   Hash Algorithm: ")
                    .append(
                            ObjectIdentifierTranslator.translate(
                                    certificateStatus.getHashAlgorithmIdentifier()));
            sb.append("\n   Issuer Name Hash: ")
                    .append("0x")
                    .append(Hex.toHexString(certificateStatus.getIssuerNameHash()));
            sb.append("\n   Issuer Key Hash: ")
                    .append("0x")
                    .append(Hex.toHexString(certificateStatus.getIssuerKeyHash()));
            sb.append("\n   Serial Number: ")
                    .append("0x")
                    .append(certificateStatus.getSerialNumber().toString(16));
            sb.append("\n   Certificate Status: ");
            sb.append(RevocationStatus.translate(certificateStatus.getCertificateStatus()));
            if (certificateStatus
                    .getCertificateStatus()
                    .equals(RevocationStatus.translate("revoked"))) {
                sb.append("\n    Revocation Time: ")
                        .append(formatDate(certificateStatus.getRevocationTime()));
                if (certificateStatus.getRevocationReason() != null) {
                    sb.append("\n    Revocation Reason: ");
                    sb.append(CrlReason.translate(certificateStatus.getRevocationReason()));
                }
            }
            sb.append("\n   Last Update: ")
                    .append(formatDate(certificateStatus.getTimeOfLastUpdate()));
            sb.append("\n   Next Update: ")
                    .append(formatDate(certificateStatus.getTimeOfNextUpdate()));
        }

        sb.append("\n Signature Algorithm: ")
                .append(ObjectIdentifierTranslator.translate(getSignatureAlgorithmIdentifier()));

        if (includeSignatureAndCertificate) {
            if (signature != null) {
                sb.append("\n Signature: ");
                sb.append(ArrayConverter.bytesToHexString(signature));
            }

            if (getCertificate() != null) {
                try {
                    String certificateBytes =
                            ArrayConverter.bytesToHexString(getResponseCertificateBytes());
                    sb.append("\n Certificate:").append(certificateBytes);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return sb.toString();
    }
}
