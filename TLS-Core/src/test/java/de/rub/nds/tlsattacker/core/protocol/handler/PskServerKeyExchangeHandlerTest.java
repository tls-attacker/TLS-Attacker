/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PskServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.PskServerKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.PskServerKeyExchangeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PskServerKeyExchangeHandlerTest {

    private PskServerKeyExchangeHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PskServerKeyExchangeHandler(context);

    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class PskServerKeyExchangeHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof PskServerKeyExchangeParser);
    }

    /**
     * Test of getPreparator method, of class PskServerKeyExchangeHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PskServerKeyExchangeMessage()) instanceof PskServerKeyExchangePreparator);
    }

    /**
     * Test of getSerializer method, of class PskServerKeyExchangeHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PskServerKeyExchangeMessage()) instanceof PskServerKeyExchangeSerializer);
    }
}
