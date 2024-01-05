/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import org.junit.jupiter.api.Test;

public class UnknownHandlerTest
        extends AbstractProtocolMessageHandlerTest<UnknownMessage, UnknownMessageHandler> {

    public UnknownHandlerTest() {
        super(UnknownMessage::new, (TlsContext context) -> new UnknownMessageHandler(context));
    }

    /** Test of adjustContext method, of class UnknownHandler. */
    @Test
    @Override
    public void testadjustContext() {
        UnknownMessage message = new UnknownMessage();
        handler.adjustContext(message);
    }
}
