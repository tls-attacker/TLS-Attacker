/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.RetransmitMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.RetransmitMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.RetransmitMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RetransmitMessageHandlerTest {

    private RetransmitMessageHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new RetransmitMessageHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class RetransmitMessageHandler.
     */
    @Test(expected = UnsupportedOperationException.class)
    public void testGetParser() {
        handler.getParser(new byte[1], 0);
    }

    /**
     * Test of getPreparator method, of class RetransmitMessageHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new RetransmitMessage(new byte[1])) instanceof RetransmitMessagePreparator);
    }

    /**
     * Test of getSerializer method, of class RetransmitMessageHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new RetransmitMessage(new byte[1])) instanceof RetransmitMessageSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class RetransmitMessageHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        RetransmitMessage message = new RetransmitMessage(new byte[] { 0, 1, 2, 34, });
        handler.adjustTLSContext(message);
        // TODO make sure nothing changed
    }

}
