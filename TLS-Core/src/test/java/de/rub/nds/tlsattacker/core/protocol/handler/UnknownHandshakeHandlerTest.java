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
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownHandshakeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownHandshakePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownHandshakeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class UnknownHandshakeHandlerTest {

    private UnknownHandshakeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new UnknownHandshakeHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of adjustTLSContext method, of class UnknownHandshakeHandler.
     */
    @Test
    public void testAdjustTLSContext() {
    }

    /**
     * Test of getParser method, of class UnknownHandshakeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof UnknownHandshakeParser);
    }

    /**
     * Test of getPreparator method, of class UnknownHandshakeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new UnknownHandshakeMessage()) instanceof UnknownHandshakePreparator);
    }

    /**
     * Test of getSerializer method, of class UnknownHandshakeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new UnknownHandshakeMessage()) instanceof UnknownHandshakeSerializer);
    }

}
