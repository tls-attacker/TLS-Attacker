/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.*;

public class ApplicationMessageHandlerTest {

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    private ApplicationMessageHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ApplicationMessageHandler(context);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of adjustContext method, of class ApplicationMessageHandler.
     */
    @Test
    public void testadjustContext() {
        ApplicationMessage message = new ApplicationMessage();
        message.setData(new byte[] { 0, 1, 2, 3, 4, 5, 6 });
        handler.adjustContext(message);
        // TODO test that nothing changes (mockito) // ugly
    }

}
