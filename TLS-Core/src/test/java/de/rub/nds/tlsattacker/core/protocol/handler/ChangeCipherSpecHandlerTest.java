/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class ChangeCipherSpecHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                ChangeCipherSpecMessage, ChangeCipherSpecHandler> {

    public ChangeCipherSpecHandlerTest() {
        super(ChangeCipherSpecMessage::new, ChangeCipherSpecHandler::new);
    }

    /** Test of adjustContext method, of class ChangeCipherSpecHandler. */
    @Test
    @Override
    public void testadjustContext() {
        ChangeCipherSpecMessage message = new ChangeCipherSpecMessage();
        context.setSelectedCipherSuite(CipherSuite.getImplemented().get(0));
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustContext(message);
        // TODO check that change did actually work
    }
}
