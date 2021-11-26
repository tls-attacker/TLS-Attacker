/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
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
     * Test of adjustContext method, of class ServerHelloDoneHandler.
     */
    @Test
    public void testadjustContext() {
        ServerHelloDoneMessage message = new ServerHelloDoneMessage();
        handler.adjustContext(message);
        // TODO make sure nothing changed
    }

}
