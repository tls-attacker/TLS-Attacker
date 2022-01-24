/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import org.junit.Before;
import org.junit.Test;

public class UnknownHandlerTest {

    private UnknownMessageHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new UnknownMessageHandler(context, ProtocolMessageType.UNKNOWN);
    }

    /**
     * Test of adjustContext method, of class UnknownHandler.
     */
    @Test
    public void testadjustContext() {
        UnknownMessage message = new UnknownMessage(context.getConfig(), ProtocolMessageType.UNKNOWN);
        handler.adjustContext(message);
    }

}
