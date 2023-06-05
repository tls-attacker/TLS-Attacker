/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class ExtendedMasterSecretExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                ExtendedMasterSecretExtensionMessage, ExtendedMasterSecretExtensionHandler> {

    public ExtendedMasterSecretExtensionHandlerTest() {
        super(ExtendedMasterSecretExtensionMessage::new, ExtendedMasterSecretExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        ExtendedMasterSecretExtensionMessage msg = new ExtendedMasterSecretExtensionMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustContext(msg);

        assertTrue(context.isExtensionProposed(ExtensionType.EXTENDED_MASTER_SECRET));
        assertFalse(context.isExtensionNegotiated(ExtensionType.EXTENDED_MASTER_SECRET));
        assertFalse(context.isUseExtendedMasterSecret());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        handler.adjustContext(msg);
        assertTrue(context.isExtensionProposed(ExtensionType.EXTENDED_MASTER_SECRET));
        assertTrue(context.isExtensionNegotiated(ExtensionType.EXTENDED_MASTER_SECRET));
        assertTrue(context.isUseExtendedMasterSecret());
    }
}
