/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import org.junit.jupiter.api.Test;

public class ServerHelloDoneHandlerTest
    extends AbstractTlsMessageHandlerTest<ServerHelloDoneMessage, ServerHelloDoneHandler> {

    public ServerHelloDoneHandlerTest() {
        super(ServerHelloDoneMessage::new, ServerHelloDoneHandler::new);
    }

    /**
     * Test of adjustTLSContext method, of class ServerHelloDoneHandler.
     */
    @Test
    @Override
    public void testAdjustTLSContext() {
        ServerHelloDoneMessage message = new ServerHelloDoneMessage();
        handler.adjustTLSContext(message);
        // TODO make sure nothing changed
    }

}
