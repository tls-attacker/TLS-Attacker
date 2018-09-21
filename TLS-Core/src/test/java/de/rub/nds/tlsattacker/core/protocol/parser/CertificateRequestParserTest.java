/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateRequestParserTest {

    // private static byte[] SSL3_CERTREQ_MSG =
    // ArrayConverter.hexStringToByteArray("0d000006030102400000");
    private static final byte[] RSA_DSS_ECDSA_TYPES = ArrayConverter.hexStringToByteArray("010240");

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
                        RSA_DSS_ECDSA_TYPES,
                        30,
                        ArrayConverter
                                .hexStringToByteArray("060106020603050105020503040104020403030103020303020102020203"),
                        0, null, ProtocolVersion.TLS12 },
                /*
                 * { SSL3_CERTREQ_MSG, 0, SSL3_CERTREQ_MSG,
                 * HandshakeMessageType.CERTIFICATE_REQUEST, 6, 3,
                 * RSA_DSS_ECDSA_TYPES, 0,null, 0, null,ProtocolVersion.SSL3 }
                 */});
        // Testdata is correct, however Certificate request and other
        // Client-Authentication related messages are not yet supported for
        // TLS-Version < 1.2
    }

    private byte[] message;
    private HandshakeMessageType type;
    private int length;
    private int certTypesCount;
    private byte[] certTypes;
    private int sigHashAlgsLength;
    private byte[] sigHashAlgs;
    private int distinguishedNamesLength;
    private byte[] disitinguishedNames;
    private ProtocolVersion version;

    public CertificateRequestParserTest(byte[] message, int start, byte[] expectedPart, HandshakeMessageType type,
            int length, int certTypesCount, byte[] certTypes, int sigHashAlgsLength, byte[] sigHashAlgs,
            int distinguishedNamesLength, byte[] disitinguishedNames, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.length = length;
        this.certTypesCount = certTypesCount;
        this.certTypes = certTypes;
        this.sigHashAlgsLength = sigHashAlgsLength;
        this.sigHashAlgs = sigHashAlgs;
        this.distinguishedNamesLength = distinguishedNamesLength;
        this.disitinguishedNames = disitinguishedNames;
        this.version = version;
    }

    /**
     * Test of parse method, of class CertificateRequestParser.
     */
    @Test
    public void testParse() {
        CertificateRequestParser parser = new CertificateRequestParser(0, message, version);
        CertificateRequestMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
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
