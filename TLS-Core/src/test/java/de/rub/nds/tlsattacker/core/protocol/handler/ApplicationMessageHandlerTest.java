/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import org.junit.jupiter.api.Test;

public class ApplicationMessageHandlerTest
    extends AbstractTlsMessageHandlerTest<ApplicationMessage, ApplicationMessageHandler> {

    ApplicationMessageHandlerTest() {
        super(ApplicationMessage::new, ApplicationMessageHandler::new);
    }

    /**
     * Test of adjustTLSContext method, of class ApplicationMessageHandler.
     */
    @Test
    @Override
    public void testAdjustTLSContext() {
        ApplicationMessage message = new ApplicationMessage();
        message.setData(new byte[] { 0, 1, 2, 3, 4, 5, 6 });
        handler.adjustTLSContext(message);
        // TODO test that nothing changes (mockito) // ugly
    }

}
