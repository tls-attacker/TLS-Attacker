/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import org.junit.jupiter.api.Test;

public class UserMappingExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                UserMappingExtensionMessage, UserMappingExtensionHandler> {
    private final UserMappingExtensionHintType hintType =
            UserMappingExtensionHintType.UPN_DOMAIN_HINT;

    public UserMappingExtensionHandlerTest() {
        super(UserMappingExtensionMessage::new, UserMappingExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        UserMappingExtensionMessage msg = new UserMappingExtensionMessage();
        msg.setUserMappingType(hintType.getValue());
        handler.adjustContext(msg);
        assertTrue(context.isExtensionProposed(ExtensionType.USER_MAPPING));
        assertEquals(hintType.getValue(), context.getUserMappingExtensionHintType().getValue());
    }
}
