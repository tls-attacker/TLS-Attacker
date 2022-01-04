/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class EncryptThenMacExtensionHandlerTest {

    private EncryptThenMacExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new EncryptThenMacExtensionHandler(context);
    }

    @Test
    public void testadjustContext() {
        EncryptThenMacExtensionMessage message = new EncryptThenMacExtensionMessage();
        handler.adjustContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.ENCRYPT_THEN_MAC));
    }
}
