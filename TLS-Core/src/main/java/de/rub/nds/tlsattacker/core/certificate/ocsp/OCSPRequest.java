/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import com.google.common.io.ByteStreams;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;

public class OCSPRequest {

    private final Logger LOGGER = LogManager.getLogger();
    private final Certificate cert;
    private final CertificateInformationExtractor infoExtractorMain;
    private Certificate issuerCert;
    private CertificateInformationExtractor infoExtractorIssuer;
    private URL serverUrl;

    // TODO: Better way to deal with exceptions
    public OCSPRequest(org.bouncycastle.crypto.tls.Certificate certChain) {
        this.cert = certChain.getCertificateAt(0);
        this.infoExtractorMain = new CertificateInformationExtractor(cert);

        try {
            this.serverUrl = new URL(infoExtractorMain.getOcspServerUrl());
        } catch (Exception e) {
            LOGGER.error("An error occurred during the parsing of the certificate's ASN.1 structure. Please set the OCSP Server URL manually.");
            LOGGER.error(e.getStackTrace());
        }

        // If we have an issuerCert, import it too, as we need it for the
        // IssuerKeyHash
        if (certChain.getLength() > 1) {
            this.issuerCert = certChain.getCertificateAt(1);
            this.infoExtractorIssuer = new CertificateInformationExtractor(issuerCert);
        }
    }

    public OCSPRequest(org.bouncycastle.crypto.tls.Certificate certChain, URL serverUrl) {
        this.cert = certChain.getCertificateAt(0);
        this.infoExtractorMain = new CertificateInformationExtractor(cert);
        this.serverUrl = serverUrl;

        // If we have an issuerCert, import it too, as we need it for the
        // IssuerKeyHash
        if (certChain.getLength() > 1) {
            this.issuerCert = certChain.getCertificateAt(1);
            this.infoExtractorIssuer = new CertificateInformationExtractor(issuerCert);
        }
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

    public Certificate getCert() {
        return cert;
    }

    public Certificate getIssuerCert() {
        return issuerCert;
    }

    public byte[] makeRequest() throws IOException, NoSuchAlgorithmException {
        OCSPRequestMessage requestMessage = prepareDefaultRequestMessage();
        return makeOcspRequest(requestMessage);
    }

    public byte[] makeRequest(OCSPRequestMessage requestMessage) throws IOException, NoSuchAlgorithmException {
        return makeOcspRequest(requestMessage);
    }

    private OCSPRequestMessage prepareDefaultRequestMessage() throws IOException, NoSuchAlgorithmException {
        BigInteger serialNumber = infoExtractorMain.getSerialNumber();
        byte[] issuerNameHash;
        byte[] issuerKeyHash;

        // issuerNameHash is based on the issuer mentioned in the certificate we
        // want to check
        issuerNameHash = infoExtractorMain.getIssuerNameHash();

        // issuerKeyHash, however, is based on the public key mentioned in the
        // issuer's certificate
        if (issuerCert != null && infoExtractorIssuer != null) {
            issuerKeyHash = infoExtractorIssuer.getIssuerKeyHash();
        } else {
            issuerKeyHash = infoExtractorMain.getIssuerKeyHash();
        }

        OCSPRequestMessage requestMessage = new OCSPRequestMessage(serialNumber, issuerNameHash, issuerKeyHash);
        requestMessage.addExtension(OCSPExtensions.NONCE.getOID());
        requestMessage.addExtension(OCSPExtensions.ACCEPTABLE_RESPONSES.getOID());

        return requestMessage;
    }

    private byte[] makeOcspRequest(OCSPRequestMessage requestMessage) throws IOException, NoSuchAlgorithmException {
        byte[] encodedRequest = requestMessage.getEncodedRequest();
        HttpURLConnection httpCon = (HttpURLConnection) serverUrl.openConnection();
        httpCon.setRequestMethod("POST");
        httpCon.setRequestProperty("Content-Type", "application/ocsp-request");

        httpCon.setDoOutput(true);
        OutputStream os = httpCon.getOutputStream();
        os.write(encodedRequest);
        os.flush();
        os.close();

        int status = httpCon.getResponseCode();
        byte[] response;
        if (status == 200)
            response = ByteStreams.toByteArray(httpCon.getInputStream());
        else
            throw new RuntimeException("Response not successful: Received status code " + status);

        httpCon.disconnect();

        return response;
    }
}
