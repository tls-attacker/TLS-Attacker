/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class RenegotiationInfoExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                RenegotiationInfoExtensionMessage, RenegotiationInfoExtensionHandler> {

    private static final int EXTENSION_LENGTH = 1;
    private static final byte[] EXTENSION_INFO = new byte[] {0};

    public RenegotiationInfoExtensionHandlerTest() {
        super(RenegotiationInfoExtensionMessage::new, RenegotiationInfoExtensionHandler::new);
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        RenegotiationInfoExtensionMessage message = new RenegotiationInfoExtensionMessage();
        message.setRenegotiationInfo(EXTENSION_INFO);
        message.setExtensionLength(EXTENSION_LENGTH);
        handler.adjustTLSExtensionContext(message);
        assertArrayEquals(EXTENSION_INFO, context.getRenegotiationInfo());
    }
}
