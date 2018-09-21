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
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class UnknownHandlerTest {

    private UnknownHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new UnknownHandler(context);
    }

    /**
     * Test of getParser method, of class UnknownHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0 }, 0) instanceof UnknownParser);
    }

    /**
     * Test of getPreparator method, of class UnknownHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new UnknownMessage()) instanceof UnknownPreparator);
    }

    /**
     * Test of getSerializer method, of class UnknownHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new UnknownMessage()) instanceof UnknownSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class UnknownHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        UnknownMessage message = new UnknownMessage();
        handler.adjustTLSContext(message);
    }

}
