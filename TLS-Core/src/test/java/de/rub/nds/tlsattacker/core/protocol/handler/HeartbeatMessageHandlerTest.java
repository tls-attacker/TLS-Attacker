/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class HeartbeatMessageHandlerTest {

    private HeartbeatMessageHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new HeartbeatMessageHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of adjustTLSContext method, of class HeartbeatMessageHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        HeartbeatMessage message = new HeartbeatMessage();
        handler.adjustTLSContext(message);
        // TODO check that context did not change
    }

}
