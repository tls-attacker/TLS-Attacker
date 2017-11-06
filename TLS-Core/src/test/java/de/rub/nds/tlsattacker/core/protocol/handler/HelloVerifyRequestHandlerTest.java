/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloVerifyRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloVerifyRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloVerifyRequestSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class HelloVerifyRequestHandlerTest {

    private HelloVerifyRequestHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new HelloVerifyRequestHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class HelloVerifyRequestHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof HelloVerifyRequestParser);
    }

    /**
     * Test of getPreparator method, of class HelloVerifyRequestHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new HelloVerifyRequestMessage()) instanceof HelloVerifyRequestPreparator);
    }

    /**
     * Test of getSerializer method, of class HelloVerifyRequestHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new HelloVerifyRequestMessage()) instanceof HelloVerifyRequestSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class HelloVerifyRequestHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        HelloVerifyRequestMessage message = new HelloVerifyRequestMessage();
        message.setCookie(new byte[] { 0, 1, 2, 3 });
        handler.adjustTLSContext(message);
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, context.getDtlsCookie());
    }

}
