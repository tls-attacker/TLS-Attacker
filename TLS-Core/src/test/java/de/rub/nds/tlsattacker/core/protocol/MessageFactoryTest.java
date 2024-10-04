/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import static de.rub.nds.tlsattacker.core.protocol.MessageFactory.generateHandshakeMessage;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MessageFactoryTest {

    private TlsContext tlsContext;

    @BeforeEach
    public void setUp() {
        State state = new State(new Config());
        tlsContext = state.getTlsContext();
    }

    @Test
    public void testGenerateHandshakeMessage() {
        HandshakeMessage message =
                generateHandshakeMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, tlsContext);
        assertTrue(message instanceof ServerKeyExchangeMessage);
    }
}
