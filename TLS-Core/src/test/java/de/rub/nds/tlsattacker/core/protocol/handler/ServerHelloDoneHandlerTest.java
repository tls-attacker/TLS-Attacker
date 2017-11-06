/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloDoneParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloDonePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloDoneSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ServerHelloDoneHandlerTest {

    private ServerHelloDoneHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ServerHelloDoneHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class ServerHelloDoneHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof ServerHelloDoneParser);
    }

    /**
     * Test of getPreparator method, of class ServerHelloDoneHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ServerHelloDoneMessage()) instanceof ServerHelloDonePreparator);
    }

    /**
     * Test of getSerializer method, of class ServerHelloDoneHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ServerHelloDoneMessage()) instanceof ServerHelloDoneSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class ServerHelloDoneHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        ServerHelloDoneMessage message = new ServerHelloDoneMessage();
        handler.adjustTLSContext(message);
        // TODO make sure nothing changed
    }

}
