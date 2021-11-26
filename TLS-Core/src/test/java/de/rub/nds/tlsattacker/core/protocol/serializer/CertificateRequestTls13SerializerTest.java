/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

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
    private int certificateRequestContextLength;
    private byte[] certificateRequestContext;
    private byte[] extensionBytes;
    private ProtocolVersion version;

    public CertificateRequestTls13SerializerTest(byte[] message, int certificateRequestContextLength,
        byte[] certificateRequestContext, byte[] extensionBytes, ProtocolVersion version) {
        this.message = message;
        this.certificateRequestContextLength = certificateRequestContextLength;
        this.certificateRequestContext = certificateRequestContext;
        this.extensionBytes = extensionBytes;
        this.version = version;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class CertificateRequestSerializer.
     */
    @Test
    public void testserializeProtocolMessageContent() {
        CertificateRequestMessage msg = new CertificateRequestMessage();
        msg.setCertificateRequestContext(certificateRequestContext);
        msg.setCertificateRequestContextLength(certificateRequestContextLength);
        msg.setExtensionBytes(extensionBytes);
        msg.setExtensionsLength(msg.getExtensionBytes().getValue().length);
        CertificateRequestSerializer serializer = new CertificateRequestSerializer(msg, version);
        assertArrayEquals(this.message, serializer.serializeProtocolMessageContent());
    }

}
