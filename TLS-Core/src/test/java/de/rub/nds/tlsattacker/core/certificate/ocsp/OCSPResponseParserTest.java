/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.certificate.ocsp;

import com.google.common.io.ByteStreams;
import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.asn1.parser.ParserException;
import org.bouncycastle.crypto.tls.Certificate;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public class OCSPResponseParserTest {

    private OCSPResponse response;
    private OCSPResponse responseWithNonce;

    @Before
    public void setUp() throws IOException, ParserException {
        // Response uses DN for identification, no extensions, does not contain
        // certificate
        InputStream stream = getClass().getClassLoader().getResourceAsStream("ocsp/ocsp-response.bin");
        byte[] responseBytes = ByteStreams.toByteArray(stream);
        response = OCSPResponseParser.parseResponse(responseBytes);
        Assert.assertArrayEquals(responseBytes, response.getEncodedResponse());

        // Response uses key for identification, contains nonce extensions,
        // contains certificate
        stream = getClass().getClassLoader().getResourceAsStream("ocsp/ocsp-response-nonce.bin");
        responseBytes = ByteStreams.toByteArray(stream);
        responseWithNonce = OCSPResponseParser.parseResponse(responseBytes);
        Assert.assertArrayEquals(responseBytes, responseWithNonce.getEncodedResponse());
    }

    @Test
    public void testParseResponse() {

        Assert.assertEquals(new Integer(0), response.getResponseStatus());
        Assert.assertNull(response.getResponseDataVersion());
        Assert.assertNull(response.getNonce()); // Response contains no nonce
        Assert.assertEquals("20200615155900Z", response.getProducedAt());
        Assert.assertEquals("1.3.6.1.5.5.7.48.1.1", response.getResponseTypeIdentifier());
        Assert.assertEquals("1.2.840.113549.1.1.11", response.getSignatureAlgorithmIdentifier());
        Assert.assertTrue(response.getCertificateStatusList().get(0) instanceof CertificateStatus);

        // Response contains no certificate
        Assert.assertNull(response.getCertificate());
        byte[] expectedSignature = { -101, -64, -19, -21, 28, -104, 57, 92, -27, 69, -5, -88, -102, 28, 71, 66, -37,
            -110, -24, 73, 65, 35, 92, -1, -27, -34, -28, -77, -44, 40, -25, 36, -4, -87, -128, -92, -127, -74, 61, -54,
            90, -36, -113, 24, -83, 50, -117, -77, -77, 111, 112, 47, -95, -119, 116, -123, 34, 13, 98, 62, 86, 6, 107,
            125, -127, -1, 63, 69, -95, 40, 83, 65, 93, -32, 101, 123, -63, 41, -104, -97, 119, 16, 21, -118, 83, 40,
            21, -47, 65, -21, 41, 11, 22, -123, 7, 77, 28, 17, 28, -12, 6, -121, -81, -22, -77, -110, -54, -89, 39, 21,
            -7, -52, -114, -60, -94, 59, -122, 64, -15, 38, -101, -6, 124, 73, -36, 17, 66, -16, 30, -5, 64, 44, 97, 38,
            25, -65, 17, -109, -43, -7, -45, -44, -73, -66, 4, -57, -99, -103, -104, -18, 71, -128, -96, -83, -37, 84,
            -1, -89, -13, -26, -11, 20, 13, 81, 21, 30, 13, 62, -97, 6, -33, 119, 101, 78, -6, 54, -3, 125, 26, 34, -9,
            4, -65, -35, 100, 108, -119, -40, -51, 54, -127, 70, 119, -32, -117, -101, -59, -84, -45, 117, 31, 102, 59,
            -99, 11, -79, -58, -98, -105, 62, 2, -111, 118, -68, -126, 92, 121, -94, 85, 90, -64, 63, -125, 81, 36, -26,
            29, 94, 99, -29, -127, -58, -13, 33, 14, 115, -114, 57, 12, -75, 33, 57, 119, -64, 17, 68, 27, 27, -8, 20,
            29, 107, -101, -32, 94, -68 };

        Assert.assertArrayEquals(expectedSignature, response.getSignature());
    }

    @Test
    public void testParseResponseNonceExtension() {
        Assert.assertEquals(1337, responseWithNonce.getNonce().intValue());
    }

    @Test
    public void testParseResponseResponderDn() {
        Assert.assertNull(response.getResponderKey());

        // Check for Distinguished Name Structure
        List<Asn1Encodable> dnCountry =
            (((Asn1Sequence) ((Asn1Set) response.getResponderName().get(0)).getChildren().get(0)).getChildren());
        Assert.assertEquals("2.5.4.6", ((Asn1ObjectIdentifier) dnCountry.get(0)).getValue());
        Assert.assertEquals("US", ((Asn1PrimitivePrintableString) dnCountry.get(1)).getValue());
        List<Asn1Encodable> dnOrganization =
            (((Asn1Sequence) ((Asn1Set) response.getResponderName().get(1)).getChildren().get(0)).getChildren());
        Assert.assertEquals("2.5.4.10", ((Asn1ObjectIdentifier) dnOrganization.get(0)).getValue());
        Assert.assertEquals("Let's Encrypt", ((Asn1PrimitivePrintableString) dnOrganization.get(1)).getValue());
        List<Asn1Encodable> dnCommonName =
            (((Asn1Sequence) ((Asn1Set) response.getResponderName().get(2)).getChildren().get(0)).getChildren());
        Assert.assertEquals("2.5.4.3", ((Asn1ObjectIdentifier) dnCommonName.get(0)).getValue());
        Assert.assertEquals("Let's Encrypt Authority X3",
            ((Asn1PrimitivePrintableString) dnCommonName.get(1)).getValue());
    }

    @Test
    public void testParseResponseResponderKey() {
        Assert.assertNull(responseWithNonce.getResponderName());

        byte[] expectedResponderKey =
            { -100, 77, 0, -103, 0, 14, -117, -80, 1, -127, 117, -95, -70, -16, -48, 37, -41, -96, 28, 71 };
        Assert.assertArrayEquals(expectedResponderKey, responseWithNonce.getResponderKey());
    }

    @Test
    public void testParseResponseCertificate() {
        Assert.assertTrue(responseWithNonce.getCertificate() instanceof Certificate);
    }
}
