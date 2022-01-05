/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.After;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
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
     * Test of adjustContext method, of class AlertHandler.
     */
    @Test
    public void testadjustContext() {
        context.setConnection(new OutboundConnection());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        AlertMessage message = new AlertMessage();
        message.setDescription(AlertDescription.ACCESS_DENIED.getValue());
        message.setLevel(AlertLevel.WARNING.getValue());
        handler.adjustContext(message);
        assertFalse(context.isReceivedFatalAlert());
        message.setLevel(AlertLevel.FATAL.getValue());
        handler.adjustContext(message);
        assertTrue(context.isReceivedFatalAlert());
    }

}
