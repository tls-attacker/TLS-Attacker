/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.ACCEPTABLE_RESPONSES;

import com.google.common.io.ByteStreams;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Base64;
import org.apache.commons.lang3.NotImplementedException;
import org.bouncycastle.asn1.x509.Certificate;

public class OCSPRequest {

    private final Certificate certificate;
    private final CertificateInformationExtractor infoExtractorMain;
    private Certificate issuerCertificate;
    private CertificateInformationExtractor infoExtractorIssuer;
    private OCSPRequestMessage requestMessage;
    private URL serverUrl;

    public OCSPRequest(org.bouncycastle.crypto.tls.Certificate certificateChain, URL serverUrl) {
        this.certificate = certificateChain.getCertificateAt(0);
        this.infoExtractorMain = new CertificateInformationExtractor(certificate);
        this.serverUrl = serverUrl;
        if (certificateChain.getLength() > 1) {
            this.issuerCertificate = certificateChain.getCertificateAt(1);
            this.infoExtractorIssuer = new CertificateInformationExtractor(issuerCertificate);
        }
    }

    public OCSPRequest(Certificate mainCertificate, Certificate issuerCertificate, URL serverUrl) {
        this.certificate = mainCertificate;
        this.infoExtractorMain = new CertificateInformationExtractor(certificate);
        this.issuerCertificate = issuerCertificate;
        this.infoExtractorIssuer = new CertificateInformationExtractor(issuerCertificate);
        this.serverUrl = serverUrl;
    }

    public URL getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(URL url) {
        this.serverUrl = url;
    }

    public void setServerUrl(String url) throws MalformedURLException {
        this.serverUrl = new URL(url);
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public Certificate getIssuerCertificate() {
        return issuerCertificate;
    }

    public OCSPRequestMessage getRequestMessage() {
        return requestMessage;
    }

    public void setRequestMessage(OCSPRequestMessage requestMessage) {
        this.requestMessage = requestMessage;
    }

    public OCSPResponse makeRequest() {
        if (this.requestMessage == null) {
            this.requestMessage = createDefaultRequestMessage();
        }
        return performRequest(requestMessage, "POST");
    }

    public OCSPResponse makeRequest(OCSPRequestMessage requestMessage) {
        return performRequest(requestMessage, "POST");
    }

    public OCSPResponse makeGetRequest() {
        if (this.requestMessage == null) {
            this.requestMessage = createDefaultRequestMessage();
        }
        return performRequest(requestMessage, "GET");
    }

    public OCSPResponse makeGetRequest(OCSPRequestMessage requestMessage) {
        return performRequest(requestMessage, "GET");
    }

    public OCSPRequestMessage createDefaultRequestMessage() {
        BigInteger serialNumber = infoExtractorMain.getSerialNumber();
        byte[] issuerNameHash;
        byte[] issuerKeyHash;

        // issuerNameHash is based on the issuer mentioned in the certificate we
        // want to check
        issuerNameHash = infoExtractorMain.getIssuerNameHash();

        // issuerKeyHash, however, is based on the public key mentioned in the
        // issuer's certificate
        if (issuerCertificate != null && infoExtractorIssuer != null) {
            issuerKeyHash = infoExtractorIssuer.getIssuerKeyHash();
        } else {
            issuerKeyHash = infoExtractorMain.getIssuerKeyHash();
        }

        OCSPRequestMessage requestMessage =
                new OCSPRequestMessage(issuerNameHash, issuerKeyHash, serialNumber);
        requestMessage.addExtension(ACCEPTABLE_RESPONSES.getOID());

        return requestMessage;
    }

    private OCSPResponse performRequest(OCSPRequestMessage requestMessage, String requestMethod) {
        try {

            byte[] encodedRequest = requestMessage.getEncodedRequest();
            HttpURLConnection httpCon = null;
            if (requestMethod.equals("POST")) {
                httpCon = (HttpURLConnection) serverUrl.openConnection();
                httpCon.setRequestMethod("POST");
                httpCon.setRequestProperty("Content-Type", "application/ocsp-request");

                httpCon.setDoOutput(true);
                try (OutputStream os = httpCon.getOutputStream()) {
                    os.write(encodedRequest);
                }
            } else if (requestMethod.equals("GET")) {
                byte[] encoded = Base64.getEncoder().encode(encodedRequest);
                URL requestUrl = new URL(serverUrl.toExternalForm() + "/" + new String(encoded));
                httpCon = (HttpURLConnection) requestUrl.openConnection();
                httpCon.setRequestMethod("GET");
            } else {
                throw new NotImplementedException("Request type is neither POST nor GET.");
            }

            httpCon.setConnectTimeout(5000);
            int status = httpCon.getResponseCode();
            byte[] response;
            if (status == 200) {
                response = ByteStreams.toByteArray(httpCon.getInputStream());
            } else {
                throw new RuntimeException(
                        "Response not successful: Received status code " + status);
            }

            httpCon.disconnect();

            return OCSPResponseParser.parseResponse(response);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
