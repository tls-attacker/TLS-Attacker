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

public class OcspRequest {

    private final Logger LOGGER = LogManager.getLogger();
    private Certificate cert;
    private URL ocspServerUrl;
    private OcspRequestCertificateInformationExtractor infoExtractor;

    public OcspRequest(Certificate cert) {
        this.cert = cert;
        this.infoExtractor = new OcspRequestCertificateInformationExtractor(cert);

        try {
            this.ocspServerUrl = new URL(infoExtractor.getOcspServerUrl());
        } catch (Exception e) {
            LOGGER.error("An error occurred during the parsing of the certificate's ASN.1 structure. Please set it manually.");
            LOGGER.error(e.getStackTrace());
        }

    }

    public OcspRequest(Certificate cert, URL ocspServerUrl) {
        this.cert = cert;
        this.ocspServerUrl = ocspServerUrl;
        this.infoExtractor = new OcspRequestCertificateInformationExtractor(cert);
    }

    public void setOcspServerUrl(String url) throws MalformedURLException {
        this.ocspServerUrl = new URL(url);
    }

    public void setOcspServerUrl(URL url) {
        this.ocspServerUrl = url;
    }

    public byte[] makeRequest() throws IOException, NoSuchAlgorithmException {
        BigInteger serialNumber = infoExtractor.getSerialNumber();
        byte[] issuerNameHash = infoExtractor.getIssuerNameHash();
        byte[] issuerKeyHash = infoExtractor.getIssuerKeyHash();

        OcspRequestMessage ocspRequestMessage = new OcspRequestMessage(serialNumber, issuerNameHash, issuerKeyHash);
        byte[] ocspEncodedRequest = ocspRequestMessage.getEncodedRequest();

        HttpURLConnection con = (HttpURLConnection) ocspServerUrl.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/ocsp-request");

        con.setDoOutput(true);
        OutputStream os = con.getOutputStream();
        os.write(ocspEncodedRequest);
        os.flush();
        os.close();

        int status = con.getResponseCode();
        byte[] response = ByteStreams.toByteArray(con.getInputStream());

        con.disconnect();

        return response;
    }
}
