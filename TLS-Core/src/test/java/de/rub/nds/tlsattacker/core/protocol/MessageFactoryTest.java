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
import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MessageFactoryTest {

    private TlsContext tlsContext;

    @BeforeEach
    public void setUp() {
        tlsContext = new TlsContext();
    }

    @Test
    public void testGenerateHandshakeMessage() {
        HandshakeMessage message =
                generateHandshakeMessage(HandshakeMessageType.SERVER_KEY_EXCHANGE, tlsContext);
        assertTrue(message instanceof ServerKeyExchangeMessage);
    }
}
