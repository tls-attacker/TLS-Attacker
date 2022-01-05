/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateRequestTls13ParserTest;
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
    private HandshakeMessageType type;
    private int certificateRequestContextLength;
    private byte[] certificateRequestContext;
    private int extensionLength;
    private byte[] extensionBytes;
    private ProtocolVersion version;

    public CertificateRequestTls13SerializerTest(byte[] message, HandshakeMessageType type,
        int certificateRequestContextLength, byte[] certificateRequestContext, int extensionLength,
        byte[] extensionBytes, ProtocolVersion version) {
        this.message = message;
        this.type = type;
        this.certificateRequestContextLength = certificateRequestContextLength;
        this.certificateRequestContext = certificateRequestContext;
        this.extensionLength = extensionLength;
        this.extensionBytes = extensionBytes;
        this.version = version;
    }

    /**
     * Test of serializeHandshakeMessageContent method, of class CertificateRequestSerializer.
     */
    @Test
    public void testSerializeHandshakeMessageContent() {
        CertificateRequestMessage msg = new CertificateRequestMessage();
        msg.setCompleteResultingMessage(message);
        msg.setLength(message.length - HandshakeByteLength.MESSAGE_LENGTH_FIELD - HandshakeByteLength.MESSAGE_TYPE);
        msg.setType(type.getValue());
        msg.setCertificateRequestContext(certificateRequestContext);
        msg.setCertificateRequestContextLength(certificateRequestContextLength);
        msg.setExtensionsLength(extensionLength);
        msg.setExtensionBytes(extensionBytes);
        CertificateRequestSerializer serializer = new CertificateRequestSerializer(msg, version);
        assertArrayEquals(this.message, serializer.serialize());
    }

}
