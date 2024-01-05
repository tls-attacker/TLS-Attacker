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

import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import org.junit.jupiter.api.Test;

public class SrpExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<SRPExtensionMessage, SRPExtensionHandler> {

    private static final byte[] SRP_IDENTIFIER = new byte[] {0x00, 0x01, 0x02, 0x03};
    private static final int SRP_IDENTIFIER_LENGTH = 4;

    public SrpExtensionHandlerTest() {
        super(SRPExtensionMessage::new, SRPExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        SRPExtensionMessage msg = new SRPExtensionMessage();
        msg.setSrpIdentifier(SRP_IDENTIFIER);
        msg.setSrpIdentifierLength(SRP_IDENTIFIER_LENGTH);
        handler.adjustTLSExtensionContext(msg);
        assertArrayEquals(SRP_IDENTIFIER, context.getSecureRemotePasswordExtensionIdentifier());
    }
}
