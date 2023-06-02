/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import static org.junit.jupiter.api.Assertions.*;

import com.google.common.io.ByteStreams;
import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import de.rub.nds.tlsattacker.core.util.Asn1ToolInitializer;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class CertificateStatusParserTest {

    private static CertificateStatus certificateStatusGood;
    private static CertificateStatus certificateStatusRevoked;

    @BeforeAll
    public static void setUpClass() throws IOException, ParserException {
        Asn1ToolInitializer.initAsn1Tool();

        // Certificate Status with a 'good' status
        byte[] certificateStatusBytes;
        try (InputStream stream =
                CertificateStatusParserTest.class
                        .getClassLoader()
                        .getResourceAsStream("ocsp/certificatestatus-good.bin")) {
            assertNotNull(stream);
            certificateStatusBytes = ByteStreams.toByteArray(stream);
        }

        Asn1Parser asn1Parser = new Asn1Parser(certificateStatusBytes, false);
        List<Asn1Encodable> decodedResponse = asn1Parser.parse(ParseOcspTypesContext.NAME);
        Asn1Sequence certificateStatusObject = (Asn1Sequence) decodedResponse.get(0);

        certificateStatusGood =
                CertificateStatusParser.parseCertificateStatus(certificateStatusObject);
        assertSame(certificateStatusObject, certificateStatusGood.getCertificateStatusSequence());

        // Certificate Status with a 'revoked' status
        try (InputStream stream =
                CertificateStatusParserTest.class
                        .getClassLoader()
                        .getResourceAsStream("ocsp/certificatestatus-revoked.bin")) {
            assertNotNull(stream);
            certificateStatusBytes = ByteStreams.toByteArray(stream);
        }

        asn1Parser = new Asn1Parser(certificateStatusBytes, false);
        decodedResponse = asn1Parser.parse(ParseOcspTypesContext.NAME);
        certificateStatusObject = (Asn1Sequence) decodedResponse.get(0);

        certificateStatusRevoked =
                CertificateStatusParser.parseCertificateStatus(certificateStatusObject);
        assertSame(
                certificateStatusObject, certificateStatusRevoked.getCertificateStatusSequence());
    }

    @Test
    public void testParseCertificateStatus() {
        assertEquals("1.3.14.3.2.26", certificateStatusGood.getHashAlgorithmIdentifier());

        byte[] expectedNameHash = {
            126, -26, 106, -25, 114, -102, -77, -4, -8, -94, 32, 100, 108, 22, -95, 45, 96, 113, 8,
            93
        };
        byte[] expectedKeyHash = {
            -88, 74, 106, 99, 4, 125, -35, -70, -26, -47, 57, -73, -90, 69, 101, -17, -13, -88, -20,
            -95
        };
        BigInteger expectedSerialNumber =
                new BigInteger("403767931667699214058966529413005128395827");
        assertArrayEquals(expectedNameHash, certificateStatusGood.getIssuerNameHash());
        assertArrayEquals(expectedKeyHash, certificateStatusGood.getIssuerKeyHash());
        assertEquals(expectedSerialNumber, certificateStatusGood.getSerialNumber());

        assertEquals("20200615150000Z", certificateStatusGood.getTimeOfLastUpdate());
        assertEquals("20200622150000Z", certificateStatusGood.getTimeOfNextUpdate());
    }

    @Test
    public void testParseCertificateStatusGood() {
        // Certificate has "good" status
        assertEquals(Integer.valueOf(0), certificateStatusGood.getCertificateStatus());
        assertNull(certificateStatusGood.getRevocationTime());
        assertNull(certificateStatusGood.getRevocationReason());
    }

    @Test
    public void testParseCertificateStatusRevoked() {
        // Certificate has "revoked" status, but no reason
        assertEquals(Integer.valueOf(1), certificateStatusRevoked.getCertificateStatus());
        assertEquals("20200423141917Z", certificateStatusRevoked.getRevocationTime());
        assertNull(certificateStatusRevoked.getRevocationReason());
    }
}
