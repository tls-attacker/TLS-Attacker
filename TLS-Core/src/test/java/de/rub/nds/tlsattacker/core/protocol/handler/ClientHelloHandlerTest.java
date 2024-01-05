/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import org.junit.jupiter.api.Test;

public class ClientHelloHandlerTest
        extends AbstractProtocolMessageHandlerTest<ClientHelloMessage, ClientHelloHandler> {

    public ClientHelloHandlerTest() {
        super(ClientHelloMessage::new, ClientHelloHandler::new);
    }

    /** Test of adjustContext method, of class ClientHelloHandler. */
    @Test
    @Override
    public void testadjustContext() {
        ClientHelloMessage message = new ClientHelloMessage();
        message.setCompleteResultingMessage(new byte[0]);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setCompressions(new byte[] {0, 1});
        message.setCipherSuites(new byte[] {0x00, 0x01, 0x00, 0x02});
        message.setSessionId(new byte[] {6, 6, 6});
        message.setProtocolVersion(ProtocolVersion.TLS12.getValue());

        handler.adjustContext(message);
        assertArrayEquals(context.getClientRandom(), new byte[] {0, 1, 2, 3, 4, 5});
        assertTrue(context.getClientSupportedCompressions().contains(CompressionMethod.DEFLATE));
        assertTrue(context.getClientSupportedCompressions().contains(CompressionMethod.NULL));
        assertEquals(2, context.getClientSupportedCompressions().size());
        assertArrayEquals(context.getClientSessionId(), new byte[] {6, 6, 6});
        assertEquals(2, context.getClientSupportedCipherSuites().size());
        assertTrue(
                context.getClientSupportedCipherSuites()
                        .contains(CipherSuite.TLS_RSA_WITH_NULL_SHA));
        assertTrue(
                context.getClientSupportedCipherSuites()
                        .contains(CipherSuite.TLS_RSA_WITH_NULL_MD5));
        assertNull(context.getDtlsCookie());
        assertArrayEquals(
                context.getHighestClientProtocolVersion().getValue(),
                ProtocolVersion.TLS12.getValue());
    }

    @Test
    public void testadjustContextWithCookie() {
        ClientHelloMessage message = new ClientHelloMessage();
        message.setCompleteResultingMessage(new byte[0]);
        message.setUnixTime(new byte[] {0, 1, 2});
        message.setRandom(new byte[] {0, 1, 2, 3, 4, 5});
        message.setCompressions(new byte[] {0, 1});
        message.setCipherSuites(new byte[] {0x00, 0x01, 0x00, 0x02});
        message.setSessionId(new byte[] {6, 6, 6});
        message.setCookie(
                new byte[] {
                    2, 2, 3,
                });
        message.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        handler.adjustContext(message);
        assertArrayEquals(context.getClientRandom(), new byte[] {0, 1, 2, 3, 4, 5});
        assertTrue(context.getClientSupportedCompressions().contains(CompressionMethod.DEFLATE));
        assertTrue(context.getClientSupportedCompressions().contains(CompressionMethod.NULL));
        assertEquals(2, context.getClientSupportedCompressions().size());
        assertArrayEquals(context.getClientSessionId(), new byte[] {6, 6, 6});
        assertEquals(2, context.getClientSupportedCipherSuites().size());
        assertTrue(
                context.getClientSupportedCipherSuites()
                        .contains(CipherSuite.TLS_RSA_WITH_NULL_SHA));
        assertTrue(
                context.getClientSupportedCipherSuites()
                        .contains(CipherSuite.TLS_RSA_WITH_NULL_MD5));
        assertArrayEquals(context.getDtlsCookie(), new byte[] {2, 2, 3});
        assertArrayEquals(
                context.getHighestClientProtocolVersion().getValue(),
                ProtocolVersion.TLS12.getValue());
    }

    // TODO test with extensions
}
