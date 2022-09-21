/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class UnknownHandshakeHandlerTest
    extends AbstractTlsMessageHandlerTest<UnknownHandshakeMessage, UnknownHandshakeHandler> {

    public UnknownHandshakeHandlerTest() {
        super(UnknownHandshakeMessage::new, UnknownHandshakeHandler::new);
    }

    @Test
    @Disabled("Not implemented")
    @Override
    public void testAdjustTLSContext() {
    }
}
