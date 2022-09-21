/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class EncryptedExtensionsHandlerTest
    extends AbstractTlsMessageHandlerTest<EncryptedExtensionsMessage, EncryptedExtensionsHandler> {

    public EncryptedExtensionsHandlerTest() {
        super(EncryptedExtensionsMessage::new, EncryptedExtensionsHandler::new);
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
    }

    /**
     * Test of adjustTLSContext method, of class EncryptedExtensionsHandler.
     */
    @Test
    @Override
    public void testAdjustTLSContext() {
        EncryptedExtensionsMessage message = new EncryptedExtensionsMessage();
        handler.adjustTLSContext(message);

        assertTrue(context.getProposedExtensions().isEmpty());
        assertTrue(context.getNegotiatedExtensionSet().isEmpty());
    }

    /**
     * Test of adjustTLSContext method, of class EncryptedExtensionsHandler.
     */
    @Test
    public void testAdjustTLSContextWithSNI() {
        EncryptedExtensionsMessage message = new EncryptedExtensionsMessage();
        // "[T]he server SHALL include an extension of type 'server_name' in the
        // (extended) server hello. The
        // 'extension_data' field of this extension SHALL be empty."
        message.addExtension(new ServerNameIndicationExtensionMessage());
        handler.adjustTLSContext(message);

        assertTrue(context.isExtensionNegotiated(ExtensionType.SERVER_NAME_INDICATION));
    }

}
