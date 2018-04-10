/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.AlertParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.AlertPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.AlertSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class AlertHandlerTest {

    private AlertHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new AlertHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getParser method, of class AlertHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof AlertParser);
    }

    /**
     * Test of getPreparator method, of class AlertHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new AlertMessage()) instanceof AlertPreparator);
    }

    /**
     * Test of getSerializer method, of class AlertHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new AlertMessage()) instanceof AlertSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class AlertHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        AlertMessage message = new AlertMessage();
        message.setDescription(AlertDescription.ACCESS_DENIED.getValue());
        message.setLevel(AlertLevel.WARNING.getValue());
        handler.adjustTLSContext(message);
        assertFalse(context.isReceivedFatalAlert());
        message.setLevel(AlertLevel.FATAL.getValue());
        handler.adjustTLSContext(message);
        assertTrue(context.isReceivedFatalAlert());
    }

}
