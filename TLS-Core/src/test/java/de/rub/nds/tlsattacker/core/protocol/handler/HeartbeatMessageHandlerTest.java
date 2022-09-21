/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import org.junit.jupiter.api.Test;

public class HeartbeatMessageHandlerTest
    extends AbstractTlsMessageHandlerTest<HeartbeatMessage, HeartbeatMessageHandler> {

    public HeartbeatMessageHandlerTest() {
        super(HeartbeatMessage::new, HeartbeatMessageHandler::new);
    }

    /**
     * Test of adjustTLSContext method, of class HeartbeatMessageHandler.
     */
    @Test
    @Override
    public void testAdjustTLSContext() {
        HeartbeatMessage message = new HeartbeatMessage();
        handler.adjustTLSContext(message);
        // TODO check that context did not change
    }

}
