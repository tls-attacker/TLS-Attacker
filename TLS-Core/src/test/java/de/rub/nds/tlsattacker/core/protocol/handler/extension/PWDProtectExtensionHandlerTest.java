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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import org.junit.jupiter.api.Test;

public class PWDProtectExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                PWDProtectExtensionMessage, PWDProtectExtensionHandler> {

    public PWDProtectExtensionHandlerTest() {
        super(PWDProtectExtensionMessage::new, PWDProtectExtensionHandler::new);
        context.setConnection(new InboundConnection());
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        PWDProtectExtensionMessage message = new PWDProtectExtensionMessage();
        message.setUsername(
                ArrayConverter.hexStringToByteArray(
                        "DA87739AC04C2A6D222FC15E31C471451DE3FE7E78B6E3485CA21E12BFE1CB4C4191D4CD9257145CBFA26DFCA1839C1588D0F1F6"));
        handler.adjustContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.PWD_PROTECT));
        assertEquals("jens", context.getClientPWDUsername());
    }
}
