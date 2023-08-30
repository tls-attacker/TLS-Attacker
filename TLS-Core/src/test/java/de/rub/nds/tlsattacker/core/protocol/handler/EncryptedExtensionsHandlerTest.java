/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class EncryptedExtensionsHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                EncryptedExtensionsMessage, EncryptedExtensionsHandler> {

    public EncryptedExtensionsHandlerTest() {
        super(
                EncryptedExtensionsMessage::new,
                EncryptedExtensionsHandler::new,
                new Context(new State(new Config()), new InboundConnection()).getTlsContext());
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setConnection(new InboundConnection());
    }

    /** Test of adjustContext method, of class EncryptedExtensionsHandler. */
    @Test
    @Override
    public void testadjustContext() {
        EncryptedExtensionsMessage message = new EncryptedExtensionsMessage();
        handler.adjustContext(message);

        assertTrue(context.getNegotiatedExtensionSet().isEmpty());
    }

    /** Test of adjustContext method, of class EncryptedExtensionsHandler. */
    @Test
    public void testadjustContextWithSNI() {
        EncryptedExtensionsMessage message = new EncryptedExtensionsMessage();
        // "[T]he server SHALL include an extension of type 'server_name' in the
        // (extended) server hello. The
        // 'extension_data' field of this extension SHALL be empty."
        message.addExtension(new ServerNameIndicationExtensionMessage());
        handler.adjustContext(message);

        assertTrue(context.isExtensionNegotiated(ExtensionType.SERVER_NAME_INDICATION));
    }
}
