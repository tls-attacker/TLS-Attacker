/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;
import org.junit.jupiter.api.Test;

public class EncryptThenMacExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                EncryptThenMacExtensionMessage, EncryptThenMacExtensionHandler> {

    public EncryptThenMacExtensionHandlerTest() {
        super(EncryptThenMacExtensionMessage::new, EncryptThenMacExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        EncryptThenMacExtensionMessage message = new EncryptThenMacExtensionMessage();
        handler.adjustContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.ENCRYPT_THEN_MAC));
    }
}
