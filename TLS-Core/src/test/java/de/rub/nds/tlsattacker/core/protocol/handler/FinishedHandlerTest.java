/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.handler.FinishedHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.FinishedMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ECDHEServerKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.FinishedMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.FinishedMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FinishedHandlerTest {

    private FinishedHandler handler;
    private TlsContext context;

    public FinishedHandlerTest() {
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new FinishedHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class FinishedHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof FinishedMessageParser);
    }

    /**
     * Test of getPreparator method, of class FinishedHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new FinishedMessage()) instanceof FinishedMessagePreparator);
    }

    /**
     * Test of getSerializer method, of class FinishedHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new FinishedMessage()) instanceof FinishedMessageSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class FinishedHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        FinishedMessage message = new FinishedMessage();
        message.setVerifyData(new byte[] { 0, 1, 2, 3, 4 });
        handler.adjustTLSContext(message);
        // TODO check that context did not change
    }

}
