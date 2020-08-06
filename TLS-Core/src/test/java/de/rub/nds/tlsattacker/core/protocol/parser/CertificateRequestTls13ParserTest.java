/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class CertificateRequestTls13ParserTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray("0d0000020102"), 0,
                ArrayConverter.hexStringToByteArray("0d0000020102"), 2, HandshakeMessageType.CERTIFICATE_REQUEST, 1,
                ArrayConverter.hexStringToByteArray("02"), ProtocolVersion.TLS13 },
        /*
         * { SSL3_CERTREQ_MSG, 0, SSL3_CERTREQ_MSG,
         * HandshakeMessageType.CERTIFICATE_REQUEST, 6, 3, RSA_DSS_ECDSA_TYPES,
         * 0,null, 0, null,ProtocolVersion.SSL3 }
         */});
        // Testdata is correct, however Certificate request and other
        // Client-Authentication related messages are not yet supported for
        // TLS-Version < 1.2
    }

    private byte[] message;
    private HandshakeMessageType type;
    private ProtocolVersion version;
    private byte[] certificateRequestContext;
    private int certificateRequestContextLength;

    public CertificateRequestTls13ParserTest(byte[] message, int start, byte[] expectedPart, int length,
            HandshakeMessageType type, int certificateRequestContextLength, byte[] certificateRequestContext,
            ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.version = version;
        this.certificateRequestContext = certificateRequestContext;
        this.certificateRequestContextLength = certificateRequestContextLength;
    }

    @Test
    public void testParse() {
        CertificateRequestParser parser = new CertificateRequestParser(0, message, version);
        CertificateRequestMessage msg = parser.parse();
        assertArrayEquals(message, msg.getCompleteResultingMessage().getValue());
        assertTrue(msg.getCertificateRequestContextLength().getValue() == certificateRequestContextLength);
        assertArrayEquals(msg.getCertificateRequestContext().getValue(), certificateRequestContext);
    }
}
