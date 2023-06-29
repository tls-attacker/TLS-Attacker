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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import org.junit.jupiter.api.Test;

public class PasswordSaltExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                PasswordSaltExtensionMessage, PasswordSaltExtensionHandler> {

    public PasswordSaltExtensionHandlerTest() {
        super(PasswordSaltExtensionMessage::new, PasswordSaltExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        PasswordSaltExtensionMessage message = new PasswordSaltExtensionMessage();
        message.setSalt(new byte[32]);
        handler.adjustContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.PASSWORD_SALT));
        assertArrayEquals(new byte[32], context.getServerPWDSalt());
    }
}
