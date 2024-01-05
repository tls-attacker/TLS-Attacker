/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.PskServerKeyExchangeMessage;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class PskServerKeyExchangeHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                PskServerKeyExchangeMessage, PskServerKeyExchangeHandler> {

    public PskServerKeyExchangeHandlerTest() {
        super(PskServerKeyExchangeMessage::new, PskServerKeyExchangeHandler::new);
    }

    @Test
    @Disabled("Not implemented")
    @Override
    public void testadjustContext() {}
}
