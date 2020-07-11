/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateRequestParserTest;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateRequestTls13ParserTest;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignatureAndHashAlgorithmsExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignatureAndHashAlgorithmsExtensionSerializer;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class CertificateRequestTls13SerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return CertificateRequestTls13ParserTest.generateData();
    }

    private byte[] message;
    private int start;
    private int length;
    private byte[] expectedPart;
    private HandshakeMessageType type;
    private ProtocolVersion version;
    private byte[] certificateRequestContext;
    private int certificateRequestContextLength;

    public CertificateRequestTls13SerializerTest(byte[] message, int start, byte[] expectedPart, int length, HandshakeMessageType type,
            int certificateRequestContextLength, byte[] certificateRequestContext, ProtocolVersion version) {
        this.message = message;
        this.start = start;
        this.length = length;
        this.expectedPart = expectedPart;
        this.type = type;
        this.version = version;
        this.certificateRequestContext = certificateRequestContext;
        this.certificateRequestContextLength = certificateRequestContextLength;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class
     * CertificateRequestSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        CertificateRequestMessage message = new CertificateRequestMessage();
        message.setLength(length);
        message.setType(type.getValue());
        message.setCertificateRequestContext(certificateRequestContext);
        message.setCertificateRequestContextLength(certificateRequestContextLength);

        CertificateRequestSerializer serializer = new CertificateRequestSerializer(message, version);
        assertArrayEquals(expectedPart, serializer.serialize());
    }

}
