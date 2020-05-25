/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1EncapsulatingBitString;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.certificate.ObjectIdentifierTranslator;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.BASIC;

public class OCSPResponse {
    private List<CertificateStatus> certificateStatusList = new LinkedList<>();
    private byte[] encodedResponse;
    private byte[] responderKey;
    private int responseStatus = -1;
    private int responseDataVersion = 0; // 0 = OCSP v1
    private BigInteger nonce;
    private String responseTime;
    private String responseTypeIdentifier;
    private String signatureAlgorithmIdentifier;
    private Asn1Encodable signature;
    private List<Asn1Encodable> responderDn;
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

    public int getResponseStatus() {
        return responseStatus;
    }

    public void setResponseStatus(int responseStatus) {
        this.responseStatus = responseStatus;
    }

    public int getResponseDataVersion() {
        return responseDataVersion;
    }

    public void setResponseDataVersion(int responseDataVersion) {
        this.responseDataVersion = responseDataVersion;
    }

    public String getResponseTime() {
        return responseTime;
    }

    public void setResponseTime(String responseTime) {
        this.responseTime = responseTime;
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

    public Asn1Encodable getSignature() {
        return signature;
    }

    public void setSignature(Asn1Encodable signature) {
        this.signature = signature;
    }

    public List<Asn1Encodable> getResponderDn() {
        return responderDn;
    }

    public void setResponderDn(List<Asn1Encodable> responderDn) {
        this.responderDn = responderDn;
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
        DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'", Locale.ENGLISH);
        DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
        LocalDateTime date = LocalDateTime.parse(unformattedDateString, inputFormatter);
        return outputFormatter.format(date);
    }

    private String parseDn() {
        StringBuilder sb = new StringBuilder();
        for (Asn1Encodable enc : responderDn) {
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
                sb.append("\n   ").append(ObjectIdentifierTranslator.translate(oid)).append(": ").append(value);
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
        if (getResponseStatus() != 0) {
            switch (getResponseStatus()) {
                case -1:
                    // Empty object
                    break;
                case 1:
                    sb.append("\n malformedRequest");
                    break;
                case 2:
                    sb.append("\n internalError");
                    break;
                case 3:
                    sb.append("\n tryLater");
                    break;
                // case 4 is defined as unused in the RFC
                case 5:
                    sb.append("\n sigRequired");
                    break;
                case 6:
                    sb.append("\n unauthorized");
                    break;
            }
            return sb.toString();
        }

        sb.append("\n Version: ");
        if (getResponseDataVersion() == 0) {
            sb.append("1 (0x0)");
        } else {
            sb.append(Integer.toHexString(getResponseDataVersion()));
        }
        sb.append("\n Produced at: ").append(formatDate(getResponseTime()));
        sb.append("\n Response Type: ");
        if (getResponseTypeIdentifier().equals(BASIC.getOID())) {
            sb.append("OCSP Basic Response");
        } else {
            sb.append(getResponseTypeIdentifier());
        }
        if (getResponderDn() != null) {
            sb.append("\n Responder DN: ").append(parseDn());
        } else if (getResponderKey() != null) {
            sb.append("\n Responder ID: ").append(Hex.toHexString(getResponderKey()));
        }
        if (getNonce() != null) {
            sb.append("\n Nonce: ").append(getNonce().toString());
        }

        int certificateCounter = 0;

        for (CertificateStatus certificateStatus : getCertificateStatusList()) {
            certificateCounter++;
            sb.append("\n Certificate Status No. ").append(certificateCounter);
            sb.append("\n   Hash Algorithm: ").append(
                    ObjectIdentifierTranslator.translate(certificateStatus.getHashAlgorithmIdentifier()));
            sb.append("\n   Issuer Name Hash: ").append(Hex.toHexString(certificateStatus.getIssuerNameHash()));
            sb.append("\n   Issuer Key Hash: ").append(Hex.toHexString(certificateStatus.getIssuerKeyHash()));
            sb.append("\n   Serial Number: ").append("0x").append(certificateStatus.getSerialNumber().toString(16));
            sb.append("\n   Certificate Status: ");
            if (certificateStatus.getCertificateStatus() == 0) {
                sb.append("good");
            } else if (certificateStatus.getCertificateStatus() == 1) {
                sb.append("revoked");
                sb.append("\n   Time of Revocation: ").append(formatDate(certificateStatus.getTimeOfRevocation()));
                if (certificateStatus.getRevocationReason() != -1) {
                    sb.append("\n   Revocation Reason: ");
                    switch (certificateStatus.getRevocationReason()) {
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
            } else if (certificateStatus.getCertificateStatus() == 2) {
                sb.append("unknown");
            }
            sb.append("\n   Last Update: ").append(formatDate(certificateStatus.getTimeOfLastUpdate()));
            sb.append("\n   Next Update: ").append(formatDate(certificateStatus.getTimeOfNextUpdate()));
        }

        sb.append("\n Signature Algorithm: ").append(
                ObjectIdentifierTranslator.translate(getSignatureAlgorithmIdentifier()));

        byte[] signature = null;
        if (getSignature() instanceof Asn1PrimitiveBitString) {
            Asn1PrimitiveBitString signatureBitString = (Asn1PrimitiveBitString) getSignature();
            signature = signatureBitString.getValue();
        } else if (getSignature() instanceof Asn1EncapsulatingBitString) {
            Asn1EncapsulatingBitString signatureBitString = (Asn1EncapsulatingBitString) getSignature();
            signature = signatureBitString.getContent().getValue();

            // Remove leading 0x00 byte
            if (signature[0] == 0x00 && (signature.length % 2) == 1) {
                signature = Arrays.copyOfRange(signature, 1, signature.length);
            }
        }

        if (includeSignatureAndCertificate) {
            if (signature != null) {
                sb.append("\n Signature: ");
                sb.append(ArrayConverter.bytesToHexString(signature));
            }

            if (getCertificate() != null) {
                try {
                    String certificateBytes = ArrayConverter.bytesToHexString(getResponseCertificateBytes());
                    sb.append("\n Certificate:").append(certificateBytes);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return sb.toString();
    }
}
