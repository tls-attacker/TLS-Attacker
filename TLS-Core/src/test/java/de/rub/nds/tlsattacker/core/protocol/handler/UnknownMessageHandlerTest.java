/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;


public class UnknownMessageHandlerTest {

    private UnknownMessageHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new UnknownMessageHandler(context);
    }

    /**
     * Test of getParser method, of class UnknownMessageHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0 }, 0) instanceof UnknownMessageParser);
    }

    /**
     * Test of getPreparator method, of class UnknownMessageHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new UnknownMessage()) instanceof UnknownMessagePreparator);
    }

    /**
     * Test of getSerializer method, of class UnknownMessageHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new UnknownMessage()) instanceof UnknownMessageSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class UnknownMessageHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        UnknownMessage message = new UnknownMessage();
        handler.adjustTLSContext(message);
    }

}
