/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class EncryptedExtensionsHandlerTest {

    private EncryptedExtensionsHandler handler;
    private TlsContext context;

    @Before
    public void setUp() throws Exception {
        context = new TlsContext();
        // Encrypted extensions can only be sent by a server
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);

        handler = new EncryptedExtensionsHandler(context);
    }

    /**
     * Test of adjustContext method, of class EncryptedExtensionsHandler.
     */
    @Test
    public void testadjustContextWithoutExtensions() {
        EncryptedExtensionsMessage message = new EncryptedExtensionsMessage();
        handler.adjustContext(message);

        assertTrue(context.getProposedExtensions().isEmpty());
        assertTrue(context.getNegotiatedExtensionSet().isEmpty());
    }

    /**
     * Test of adjustContext method, of class EncryptedExtensionsHandler.
     */
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
