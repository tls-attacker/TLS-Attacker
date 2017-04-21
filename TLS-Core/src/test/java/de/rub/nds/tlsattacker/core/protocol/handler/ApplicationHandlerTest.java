/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.handler.ApplicationHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.AlertPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ApplicationMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ApplicationMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ApplicationHandlerTest {

    private ApplicationHandler handler;
    private TlsContext context;

    public ApplicationHandlerTest() {

    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ApplicationHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class ApplicationHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof ApplicationMessageParser);
    }

    /**
     * Test of getPreparator method, of class ApplicationHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new ApplicationMessage()) instanceof ApplicationMessagePreparator);
    }

    /**
     * Test of getSerializer method, of class ApplicationHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new ApplicationMessage()) instanceof ApplicationMessageSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class ApplicationHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        ApplicationMessage message = new ApplicationMessage();
        message.setData(new byte[] { 0, 1, 2, 3, 4, 5, 6 });
        handler.adjustTLSContext(message);
        // TODO test that nothing changes (mockito) // ugly
    }

}
