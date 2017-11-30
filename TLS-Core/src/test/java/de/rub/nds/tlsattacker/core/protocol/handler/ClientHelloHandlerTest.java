/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ClientHelloSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ClientHelloHandlerTest {

    private ClientHelloHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ClientHelloHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class ClientHelloHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof ClientHelloParser);
    }

    /**
     * Test of getPreparator method, of class ClientHelloHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ClientHelloMessage()) instanceof ClientHelloPreparator);
    }

    /**
     * Test of getSerializer method, of class ClientHelloHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ClientHelloMessage()) instanceof ClientHelloSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class ClientHelloHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        ClientHelloMessage message = new ClientHelloMessage();
        message.setUnixTime(new byte[] { 0, 1, 2 });
        message.setRandom(new byte[] { 0, 1, 2, 3, 4, 5 });
        message.setCompressions(new byte[] { 0, 1 });
        message.setCipherSuites(new byte[] { 0x00, 0x01, 0x00, 0x02 });
        message.setSessionId(new byte[] { 6, 6, 6 });
        message.setProtocolVersion(ProtocolVersion.TLS12.getValue());

        handler.adjustTLSContext(message);
        assertArrayEquals(context.getClientRandom(), new byte[] { 0, 1, 2, 3, 4, 5 });
        assertTrue(context.getClientSupportedCompressions().contains(CompressionMethod.DEFLATE));
        assertTrue(context.getClientSupportedCompressions().contains(CompressionMethod.NULL));
        assertTrue(context.getClientSupportedCompressions().size() == 2);
        assertArrayEquals(context.getClientSessionId(), new byte[] { 6, 6, 6 });
        assertTrue(context.getClientSupportedCiphersuites().size() == 2);
        assertTrue(context.getClientSupportedCiphersuites().contains(CipherSuite.TLS_RSA_WITH_NULL_SHA));
        assertTrue(context.getClientSupportedCiphersuites().contains(CipherSuite.TLS_RSA_WITH_NULL_MD5));
        assertNull(context.getDtlsCookie());
        assertArrayEquals(context.getHighestClientProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
    }

    @Test
    public void testAdjustTLSContextWithCookie() {
        ClientHelloMessage message = new ClientHelloMessage();
        message.setUnixTime(new byte[] { 0, 1, 2 });
        message.setRandom(new byte[] { 0, 1, 2, 3, 4, 5 });
        message.setCompressions(new byte[] { 0, 1 });
        message.setCipherSuites(new byte[] { 0x00, 0x01, 0x00, 0x02 });
        message.setSessionId(new byte[] { 6, 6, 6 });
        message.setCookie(new byte[] { 2, 2, 3, });
        message.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        handler.adjustTLSContext(message);
        assertArrayEquals(context.getClientRandom(), new byte[] { 0, 1, 2, 3, 4, 5 });
        assertTrue(context.getClientSupportedCompressions().contains(CompressionMethod.DEFLATE));
        assertTrue(context.getClientSupportedCompressions().contains(CompressionMethod.NULL));
        assertTrue(context.getClientSupportedCompressions().size() == 2);
        assertArrayEquals(context.getClientSessionId(), new byte[] { 6, 6, 6 });
        assertTrue(context.getClientSupportedCiphersuites().size() == 2);
        assertTrue(context.getClientSupportedCiphersuites().contains(CipherSuite.TLS_RSA_WITH_NULL_SHA));
        assertTrue(context.getClientSupportedCiphersuites().contains(CipherSuite.TLS_RSA_WITH_NULL_MD5));
        assertArrayEquals(context.getDtlsCookie(), new byte[] { 2, 2, 3 });
        assertArrayEquals(context.getHighestClientProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
    }

    // TODO test with extensions
}
