/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownHandshakeMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownHandshakeMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownHandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownHandshakeMessageHandlerTest {

    private UnknownHandshakeMessageHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new UnknownHandshakeMessageHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of adjustTLSContext method, of class UnknownHandshakeMessageHandler.
     */
    @Test
    public void testAdjustTLSContext() {
    }

    /**
     * Test of getParser method, of class UnknownHandshakeMessageHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof UnknownHandshakeMessageParser);
    }

    /**
     * Test of getPreparator method, of class UnknownHandshakeMessageHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new UnknownHandshakeMessage()) instanceof UnknownHandshakeMessagePreparator);
    }

    /**
     * Test of getSerializer method, of class UnknownHandshakeMessageHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new UnknownHandshakeMessage()) instanceof UnknownHandshakeMessageSerializer);
    }

}
