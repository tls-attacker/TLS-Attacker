/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class CertificateRequestMessageParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("0d00002603010240001e0601060206030501050205030401040204030301030203030201020202030000"),
                        0,
                        ArrayConverter
                                .hexStringToByteArray("0d00002603010240001e0601060206030501050205030401040204030301030203030201020202030000"),
                        HandshakeMessageType.CERTIFICATE_REQUEST,
                        38,
                        3,
                        ArrayConverter.hexStringToByteArray("010240"),
                        30,
                        ArrayConverter
                                .hexStringToByteArray("060106020603050105020503040104020403030103020303020102020203"),
                        0, null }, });
    }

    private byte[] message;
    private int start;
    private byte[] expectedPart;

    private HandshakeMessageType type;
    private int length;

    private int certTypesCount;
    private byte[] certTypes;
    private int sigHashAlgsLength;
    private byte[] sigHashAlgs;
    private int distinguishedNamesLength;
    private byte[] disitinguishedNames;

    public CertificateRequestMessageParserTest(byte[] message, int start, byte[] expectedPart,
            HandshakeMessageType type, int length, int certTypesCount, byte[] certTypes, int sigHashAlgsLength,
            byte[] sigHashAlgs, int distinguishedNamesLength, byte[] disitinguishedNames) {
        this.message = message;
        this.start = start;
        this.expectedPart = expectedPart;
        this.type = type;
        this.length = length;
        this.certTypesCount = certTypesCount;
        this.certTypes = certTypes;
        this.sigHashAlgsLength = sigHashAlgsLength;
        this.sigHashAlgs = sigHashAlgs;
        this.distinguishedNamesLength = distinguishedNamesLength;
        this.disitinguishedNames = disitinguishedNames;

    }

    /**
     * Test of parse method, of class CertificateRequestMessageParser.
     */
    @Test
    public void testParse() {
        CertificateRequestMessageParser parser = new CertificateRequestMessageParser(start, message,
                ProtocolVersion.TLS12);
        CertificateRequestMessage msg = parser.parse();
        assertArrayEquals(expectedPart, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getLength().getValue() == length);
        assertTrue(msg.getType().getValue() == type.getValue());
        assertTrue(msg.getClientCertificateTypesCount().getValue() == certTypesCount);
        assertArrayEquals(certTypes, msg.getClientCertificateTypes().getValue());
        assertTrue(msg.getSignatureHashAlgorithmsLength().getValue() == sigHashAlgsLength);
        assertArrayEquals(sigHashAlgs, msg.getSignatureHashAlgorithms().getValue());
        assertTrue(msg.getDistinguishedNamesLength().getValue() == distinguishedNamesLength);
        if (distinguishedNamesLength == 0) {
            assertNull(msg.getDistinguishedNames());
        } else {
            assertArrayEquals(disitinguishedNames, msg.getDistinguishedNames().getValue());
        }
    }

}
