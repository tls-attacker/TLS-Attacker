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

    private CertificateStatus certificateStatusGood;
    private CertificateStatus certificateStatusRevoked;

    @Before
    public void setUp() throws IOException, ParserException {
        Asn1ToolInitializer.initAsn1Tool();

        // Certificate Status with a 'good' status
        InputStream stream = getClass().getClassLoader().getResourceAsStream("ocsp/certificatestatus-good.bin");
        byte[] certificateStatusBytes = ByteStreams.toByteArray(stream);

        Asn1Parser asn1Parser = new Asn1Parser(certificateStatusBytes, false);
        List<Asn1Encodable> decodedResponse = asn1Parser.parse(ParseOcspTypesContext.NAME);
        Asn1Sequence certificateStatusObject = (Asn1Sequence) decodedResponse.get(0);

        certificateStatusGood = CertificateStatusParser.parseCertificateStatus(certificateStatusObject);
        Assert.assertSame(certificateStatusObject, certificateStatusGood.getCertificateStatusSequence());

        // Certificate Status with a 'revoked' status
        stream = getClass().getClassLoader().getResourceAsStream("ocsp/certificatestatus-revoked.bin");
        certificateStatusBytes = ByteStreams.toByteArray(stream);

        asn1Parser = new Asn1Parser(certificateStatusBytes, false);
        decodedResponse = asn1Parser.parse(ParseOcspTypesContext.NAME);
        certificateStatusObject = (Asn1Sequence) decodedResponse.get(0);

        certificateStatusRevoked = CertificateStatusParser.parseCertificateStatus(certificateStatusObject);
        Assert.assertSame(certificateStatusObject, certificateStatusRevoked.getCertificateStatusSequence());
    }

    @Test
    public void testParseCertificateStatus() {
        Assert.assertEquals("1.3.14.3.2.26", certificateStatusGood.getHashAlgorithmIdentifier());

        byte[] expectedNameHash =
            { 126, -26, 106, -25, 114, -102, -77, -4, -8, -94, 32, 100, 108, 22, -95, 45, 96, 113, 8, 93 };
        byte[] expectedKeyHash =
            { -88, 74, 106, 99, 4, 125, -35, -70, -26, -47, 57, -73, -90, 69, 101, -17, -13, -88, -20, -95 };
        BigInteger expectedSerialNumber = new BigInteger("403767931667699214058966529413005128395827");
        Assert.assertArrayEquals(expectedNameHash, certificateStatusGood.getIssuerNameHash());
        Assert.assertArrayEquals(expectedKeyHash, certificateStatusGood.getIssuerKeyHash());
        Assert.assertEquals(expectedSerialNumber, certificateStatusGood.getSerialNumber());

        Assert.assertEquals("20200615150000Z", certificateStatusGood.getTimeOfLastUpdate());
        Assert.assertEquals("20200622150000Z", certificateStatusGood.getTimeOfNextUpdate());
    }

    @Test
    public void testParseCertificateStatusGood() {
        // Certificate has "good" status
        Assert.assertEquals(new Integer(0), certificateStatusGood.getCertificateStatus());
        Assert.assertNull(certificateStatusGood.getRevocationTime());
        Assert.assertNull(certificateStatusGood.getRevocationReason());
    }

    @Test
    public void testParseCertificateStatusRevoked() {
        // Certificate has "revoked" status, but no reason
        Assert.assertEquals(new Integer(1), certificateStatusRevoked.getCertificateStatus());
        Assert.assertEquals("20200423141917Z", certificateStatusRevoked.getRevocationTime());
        Assert.assertNull(certificateStatusRevoked.getRevocationReason());
    }
}
