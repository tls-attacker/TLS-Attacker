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
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;

import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.ACCEPTABLE_RESPONSES;
import static de.rub.nds.tlsattacker.core.certificate.ocsp.OCSPResponseTypes.NONCE;

public class OCSPRequest {

    private final Logger LOGGER = LogManager.getLogger();
    private final Certificate certificate;
    private final CertificateInformationExtractor infoExtractorMain;
    private Certificate issuerCertificate;
    private CertificateInformationExtractor infoExtractorIssuer;
    private OCSPRequestMessage requestMessage;
    private URL serverUrl;

    // TODO: Better way to deal with exceptions
    public OCSPRequest(org.bouncycastle.crypto.tls.Certificate certChain) {
        this.certificate = certChain.getCertificateAt(0);
        this.infoExtractorMain = new CertificateInformationExtractor(certificate);
        this.issuerCertificate = certChain.getCertificateAt(1);
        this.infoExtractorIssuer = new CertificateInformationExtractor(issuerCertificate);

        prepareOcspUrl();
    }

    public OCSPRequest(org.bouncycastle.crypto.tls.Certificate certificateChain, URL serverUrl) {
        this.certificate = certificateChain.getCertificateAt(0);
        this.infoExtractorMain = new CertificateInformationExtractor(certificate);
        this.serverUrl = serverUrl;
        this.issuerCertificate = certificateChain.getCertificateAt(1);
        this.infoExtractorIssuer = new CertificateInformationExtractor(issuerCertificate);
    }

    // If no chain is given, try to recreate one with the issuer information in
    // a certificate
    public OCSPRequest(Certificate certificate) throws RuntimeException, NoSuchFieldException {
        this.certificate = certificate;
        this.infoExtractorMain = new CertificateInformationExtractor(certificate);

        prepareOcspUrl();
        prepareIssuerCertificateUrl();
    }

    public OCSPRequest(Certificate certificate, URL serverUrl) throws RuntimeException, NoSuchFieldException {
        this.certificate = certificate;
        this.infoExtractorMain = new CertificateInformationExtractor(certificate);
        this.serverUrl = serverUrl;

        prepareIssuerCertificateUrl();
    }

    public OCSPRequest(Certificate mainCertificate, Certificate issuerCertificate) throws RuntimeException {
        this.certificate = mainCertificate;
        this.infoExtractorMain = new CertificateInformationExtractor(certificate);
        this.issuerCertificate = issuerCertificate;
        this.infoExtractorIssuer = new CertificateInformationExtractor(issuerCertificate);

        prepareOcspUrl();
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

    public OCSPResponse makeRequest() throws IOException, NoSuchAlgorithmException, ParserException {
        if (this.requestMessage == null) {
            this.requestMessage = createDefaultRequestMessage();
        }
        return performRequest(requestMessage);
    }

    public OCSPResponse makeRequest(OCSPRequestMessage requestMessage) throws IOException, ParserException {
        return performRequest(requestMessage);
    }

    private void prepareOcspUrl() {
        try {
            this.serverUrl = new URL(infoExtractorMain.getOcspServerUrl());
        } catch (UnsupportedOperationException e) {
            throw new UnsupportedOperationException("This certificate does not appear to support OCSP.");
        } catch (Exception e) {
            throw new RuntimeException("An error occurred during parsing certificate for OCSP information.");
        }
    }

    private void prepareIssuerCertificateUrl() throws NoSuchFieldException {
        try {
            this.issuerCertificate = retrieveIssuerCertificate();
            this.infoExtractorIssuer = new CertificateInformationExtractor(issuerCertificate);
        } catch (NoSuchFieldException e) {
            // Checks with the Root CA as issuer are not supported yet.
            throw new NoSuchFieldException("Unable to find information about issuer.");
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract issuer information.");
        }
    }

    private Certificate retrieveIssuerCertificate() throws IOException, ParserException, NoSuchFieldException {
        /*
         * Certificate chain recreation sucks. We only support .crt /
         * DER-encoded certificates for extraction, as this seems to be the most
         * common one out there and is somewhat easy to parse with BouncyCastle.
         * This only works somewhat reliably with an intermediate CA as issuer.
         * Any root CA will likely fail, as an URL to the issuer certificate is
         * often not given in the intermediate's certificate (since they're
         * often stored locally). So take care, the following code will likely
         * fail often.
         */

        // Get URL for the issuer certificate from main certificate
        String issuerCertificateUrlString = infoExtractorMain.getCertificateIssuerUrl();
        URL issuerCertificateUrl = null;

        if (issuerCertificateUrlString != null) {
            issuerCertificateUrl = new URL(issuerCertificateUrlString);
        } else {
            throw new RuntimeException("Didn't get any issuer certificate URL from certificate.");
        }

        // Download certificate from URL
        HttpURLConnection httpCon = (HttpURLConnection) issuerCertificateUrl.openConnection();
        httpCon.setRequestMethod("GET");

        int status = httpCon.getResponseCode();
        byte[] response;
        if (status == 200)
            response = ByteStreams.toByteArray(httpCon.getInputStream());
        else
            throw new RuntimeException("Response not successful: Received status code " + status);

        httpCon.disconnect();

        // Recreate TLS certificate length information
        byte[] certificateWithLength = ArrayConverter.concatenate(
                ArrayConverter.intToBytes(response.length, HandshakeByteLength.CERTIFICATES_LENGTH), response);
        ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(
                ArrayConverter.intToBytes(certificateWithLength.length, HandshakeByteLength.CERTIFICATES_LENGTH),
                certificateWithLength));

        // Parse and create a Certificate object
        org.bouncycastle.crypto.tls.Certificate tlsCertificate = org.bouncycastle.crypto.tls.Certificate.parse(stream);
        return tlsCertificate.getCertificateAt(0);
    }

    public OCSPRequestMessage createDefaultRequestMessage() throws IOException, NoSuchAlgorithmException {
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

        OCSPRequestMessage requestMessage = new OCSPRequestMessage(serialNumber, issuerNameHash, issuerKeyHash);
        requestMessage.addExtension(ACCEPTABLE_RESPONSES.getOID());

        return requestMessage;
    }

    private OCSPResponse performRequest(OCSPRequestMessage requestMessage) throws IOException, ParserException {
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

        return OCSPResponseParser.parseResponse(response);
    }
}
