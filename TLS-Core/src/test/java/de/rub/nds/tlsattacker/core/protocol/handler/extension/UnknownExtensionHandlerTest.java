/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

public class UnknownExtensionHandlerTest {

    private UnknownExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new UnknownExtensionHandler(context);
    }

    /**
     * Test of adjustContext method, of class UnknownExtensionHandler.
     */
    @Test
    public void testadjustContext() {
        UnknownExtensionMessage msg = new UnknownExtensionMessage();
        handler.adjustContext(msg);
        // TODO Check that context does not change
    }
}
