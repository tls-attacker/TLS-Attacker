/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import de.rub.nds.tlsattacker.core.constants.MaxFragmentLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class MaxFragmentLengthExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                MaxFragmentLengthExtensionMessage, MaxFragmentLengthExtensionHandler> {

    public MaxFragmentLengthExtensionHandlerTest() {
        super(MaxFragmentLengthExtensionMessage::new, MaxFragmentLengthExtensionHandler::new);
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
    }

    /** Test of adjustContext method, of class MaxFragmentLengthExtensionHandler. */
    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        MaxFragmentLengthExtensionMessage msg = new MaxFragmentLengthExtensionMessage();
        msg.setMaxFragmentLength(new byte[] {1});
        handler.adjustTLSExtensionContext(msg);
        assertSame(context.getMaxFragmentLength(), MaxFragmentLength.TWO_9);
    }

    @Test
    public void testUndefinedAdjustment() {
        MaxFragmentLengthExtensionMessage msg = new MaxFragmentLengthExtensionMessage();
        msg.setMaxFragmentLength(new byte[] {77});
        handler.adjustContext(msg);
        assertNull(context.getMaxFragmentLength());
    }
}
