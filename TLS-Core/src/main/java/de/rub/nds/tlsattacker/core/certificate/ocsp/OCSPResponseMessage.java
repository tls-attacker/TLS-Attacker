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
import org.bouncycastle.crypto.tls.Certificate;

import java.util.LinkedList;
import java.util.List;

public class OCSPResponseMessage {
    private List<CertificateStatus> certificateStatusList = new LinkedList<>();
    private byte[] encodedResponse;
    private byte[] responderKey;
    private int responseStatus;
    private int responseDataVersion = 0; // 0 = OCSP v1
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
}
