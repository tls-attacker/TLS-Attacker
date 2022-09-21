/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import org.junit.jupiter.api.Test;

public class HelloVerifyRequestHandlerTest
    extends AbstractTlsMessageHandlerTest<HelloVerifyRequestMessage, HelloVerifyRequestHandler> {

    public HelloVerifyRequestHandlerTest() {
        super(HelloVerifyRequestMessage::new, HelloVerifyRequestHandler::new);
    }

    /**
     * Test of adjustTLSContext method, of class HelloVerifyRequestHandler.
     */
    @Test
    @Override
    public void testAdjustTLSContext() {
        HelloVerifyRequestMessage message = new HelloVerifyRequestMessage();
        message.setCookie(new byte[] { 0, 1, 2, 3 });
        handler.adjustTLSContext(message);
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, context.getDtlsCookie());
    }

}
