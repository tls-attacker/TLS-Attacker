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
    private Certificate cert;
    private Certificate issuerCert;
    private CertificateInformationExtractor infoExtractorMain;
    private CertificateInformationExtractor infoExtractorIssuer;
    private URL ocspServerUrl;

    // TODO: Better way to deal with exceptions
    public OCSPRequest(org.bouncycastle.crypto.tls.Certificate certChain) {
        this.cert = certChain.getCertificateAt(0);
        this.infoExtractorMain = new CertificateInformationExtractor(cert);

        try {
            this.ocspServerUrl = new URL(infoExtractorMain.getOcspServerUrl());
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

    public OCSPRequest(org.bouncycastle.crypto.tls.Certificate certChain, URL ocspServerUrl) {
        this.cert = certChain.getCertificateAt(0);
        this.infoExtractorMain = new CertificateInformationExtractor(cert);
        this.ocspServerUrl = ocspServerUrl;

        // If we have an issuerCert, import it too, as we need it for the
        // IssuerKeyHash
        if (certChain.getLength() > 1) {
            this.issuerCert = certChain.getCertificateAt(1);
            this.infoExtractorIssuer = new CertificateInformationExtractor(issuerCert);
        }
    }

    public void setOcspServerUrl(String url) throws MalformedURLException {
        this.ocspServerUrl = new URL(url);
    }

    public void setOcspServerUrl(URL url) {
        this.ocspServerUrl = url;
    }

    public byte[] makeRequest() throws IOException, NoSuchAlgorithmException {
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

        OCSPRequestMessage ocspRequestMessage = new OCSPRequestMessage(serialNumber, issuerNameHash, issuerKeyHash);
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
        byte[] response;
        if (status == 200)
            response = ByteStreams.toByteArray(con.getInputStream());
        else
            throw new RuntimeException("Response not successful: Received status code " + status);

        con.disconnect();

        return response;
    }
}
