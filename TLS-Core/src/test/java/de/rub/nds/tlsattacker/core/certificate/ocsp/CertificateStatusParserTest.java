/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.ocsp;

import com.google.common.io.ByteStreams;
import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.translator.ParseOcspTypesContext;
import de.rub.nds.tlsattacker.core.util.Asn1ToolInitializer;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;

public class CertificateStatusParserTest {

    @Before
    public void setUp() {
        Asn1ToolInitializer.initAsn1Tool();
    }

    @Test
    public void testParseCertificateStatus() throws IOException, ParserException {
        InputStream stream = getClass().getClassLoader().getResourceAsStream("ocsp/certificatestatus-good.bin");
        byte[] certificateStatusBytes = ByteStreams.toByteArray(stream);

        Asn1Parser asn1Parser = new Asn1Parser(certificateStatusBytes, false);
        List<Asn1Encodable> decodedResponse = asn1Parser.parse(ParseOcspTypesContext.NAME);
        Asn1Sequence certificateStatusObject = (Asn1Sequence) decodedResponse.get(0);

        CertificateStatus certificateStatus = CertificateStatusParser.parseCertificateStatus(certificateStatusObject);
        Assert.assertSame(certificateStatusObject, certificateStatus.getCertificateStatusSequence());
        Assert.assertEquals("1.3.14.3.2.26", certificateStatus.getHashAlgorithmIdentifier());

        byte[] expectedNameHash = { 126, -26, 106, -25, 114, -102, -77, -4, -8, -94, 32, 100, 108, 22, -95, 45, 96,
                113, 8, 93 };
        byte[] expectedKeyHash = { -88, 74, 106, 99, 4, 125, -35, -70, -26, -47, 57, -73, -90, 69, 101, -17, -13, -88,
                -20, -95 };
        BigInteger expectedSerialNumber = new BigInteger("403767931667699214058966529413005128395827");
        Assert.assertArrayEquals(expectedNameHash, certificateStatus.getIssuerNameHash());
        Assert.assertArrayEquals(expectedKeyHash, certificateStatus.getIssuerKeyHash());
        Assert.assertEquals(expectedSerialNumber, certificateStatus.getSerialNumber());

        Assert.assertEquals("20200615150000Z", certificateStatus.getTimeOfLastUpdate());
        Assert.assertEquals("20200622150000Z", certificateStatus.getTimeOfNextUpdate());
    }

    @Test
    public void testParseCertificateStatusGood() throws IOException, ParserException {
        InputStream stream = getClass().getClassLoader().getResourceAsStream("ocsp/certificatestatus-good.bin");
        byte[] certificateStatusBytes = ByteStreams.toByteArray(stream);

        Asn1Parser asn1Parser = new Asn1Parser(certificateStatusBytes, false);
        List<Asn1Encodable> decodedResponse = asn1Parser.parse(ParseOcspTypesContext.NAME);
        Asn1Sequence certificateStatusObject = (Asn1Sequence) decodedResponse.get(0);

        CertificateStatus certificateStatus = CertificateStatusParser.parseCertificateStatus(certificateStatusObject);

        // Certificate has "good" status
        Assert.assertEquals(0, certificateStatus.getCertificateStatus());
        Assert.assertNull(certificateStatus.getTimeOfRevocation());
        Assert.assertEquals(-1, certificateStatus.getRevocationReason());
    }

    @Test
    public void testParseCertificateStatusRevoked() throws IOException, ParserException {
        InputStream stream = getClass().getClassLoader().getResourceAsStream("ocsp/certificatestatus-revoked.bin");
        byte[] certificateStatusBytes = ByteStreams.toByteArray(stream);

        Asn1Parser asn1Parser = new Asn1Parser(certificateStatusBytes, false);
        List<Asn1Encodable> decodedResponse = asn1Parser.parse(ParseOcspTypesContext.NAME);
        Asn1Sequence certificateStatusObject = (Asn1Sequence) decodedResponse.get(0);

        CertificateStatus certificateStatus = CertificateStatusParser.parseCertificateStatus(certificateStatusObject);

        Assert.assertEquals(1, certificateStatus.getCertificateStatus());
        Assert.assertEquals("20200423141917Z", certificateStatus.getTimeOfRevocation());

        // Test response contains no revocation reason
        Assert.assertEquals(-1, certificateStatus.getRevocationReason());
    }
}
