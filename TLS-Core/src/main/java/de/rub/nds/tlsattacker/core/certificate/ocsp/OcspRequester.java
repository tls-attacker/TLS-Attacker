/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import org.apache.commons.lang3.NotImplementedException;

public class OcspRequester {

    private final X509Certificate certificate;
    private final X509Certificate issuerCertificate;
    private OcspRequestMessage requestMessage;
    private URL serverUrl;

    public OcspRequester(
            X509Certificate mainCertificate, X509Certificate issuerCertificate, URL serverUrl) {
        this.certificate = mainCertificate;
        this.issuerCertificate = issuerCertificate;
        this.serverUrl = serverUrl;
    }

    private OcspResponse performRequest(OcspRequestMessage requestMessage, String requestMethod) {
        try {

            byte[] encodedRequest = new byte[0]; // TODO requestMessage.getSerializer().serialize();
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
            OcspResponse ocspResponse;
            if (status == 200) {
                ocspResponse = new OcspResponse("ocspResponse");
                // TODO ocspResponse.getParser().parse(httpCon.getInputStream());
            } else {
                throw new RuntimeException(
                        "Response not successful: Received status code " + status);
            }

            httpCon.disconnect();
            return ocspResponse;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
