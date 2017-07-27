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
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerHelloHandlerTest {

    private ServerHelloHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ServerHelloHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getPreparator method, of class ServerHelloHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ServerHelloMessage()) instanceof ServerHelloMessagePreparator);
    }

    /**
     * Test of getSerializer method, of class ServerHelloHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ServerHelloMessage()) instanceof ServerHelloMessageSerializer);
    }

    /**
     * Test of getParser method, of class ServerHelloHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof ServerHelloParser);
    }

    /**
     * Test of adjustTLSContext method, of class ServerHelloHandler.
     */

    @Test
    public void testAdjustTLSContext() {
        ServerHelloMessage message = new ServerHelloMessage();
        message.setUnixTime(new byte[] { 0, 1, 2 });
        message.setRandom(new byte[] { 3, 4, 5 });
        message.setSelectedCompressionMethod(CompressionMethod.DEFLATE.getValue());
        message.setSelectedCipherSuite(CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384.getByteValue());
        message.setSessionId(new byte[] { 6, 6, 6 });
        message.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        handler.adjustTLSContext(message);
        assertArrayEquals(context.getServerRandom(), new byte[] { 0, 1, 2, 3, 4, 5 });
        assertTrue(context.getSelectedCompressionMethod() == CompressionMethod.DEFLATE);
        assertArrayEquals(context.getServerSessionId(), new byte[] { 6, 6, 6 });
        assertArrayEquals(context.getSelectedCipherSuite().getByteValue(),
                CipherSuite.TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384.getByteValue());
        assertArrayEquals(context.getSelectedProtocolVersion().getValue(), ProtocolVersion.TLS12.getValue());
    }

}
