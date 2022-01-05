/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.After;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class HelloVerifyRequestHandlerTest {

    private HelloVerifyRequestHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new HelloVerifyRequestHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of adjustContext method, of class HelloVerifyRequestHandler.
     */
    @Test
    public void testadjustContext() {
        HelloVerifyRequestMessage message = new HelloVerifyRequestMessage();
        message.setCookie(new byte[] { 0, 1, 2, 3 });
        handler.adjustContext(message);
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, context.getDtlsCookie());
    }

}
