/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EncryptedExtensionsParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EncryptedExtensionsPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EncryptedExtensionsSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

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
     * Test of getParser method, of class EncryptedExtensionsHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[1], 0) instanceof EncryptedExtensionsParser);
    }

    /**
     * Test of getPreparator method, of class EncryptedExtensionsHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new EncryptedExtensionsMessage()) instanceof EncryptedExtensionsPreparator);
    }

    /**
     * Test of getSerializer method, of class EncryptedExtensionsHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new EncryptedExtensionsMessage()) instanceof EncryptedExtensionsSerializer);
    }

    /**
     * Test of adjustTLSContext method, of class EncryptedExtensionsHandler.
     */
    @Test
    public void testAdjustTLSContextWithoutExtensions() {
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
