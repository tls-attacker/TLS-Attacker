/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PasswordSaltExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.PasswordSaltExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PasswordSaltExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PasswordSaltExtensionHandlerTest {
    private PasswordSaltExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new PasswordSaltExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        PasswordSaltExtensionMessage message = new PasswordSaltExtensionMessage();
        message.setSalt(new byte[32]);
        handler.adjustTLSContext(message);
        assertTrue(context.isExtensionProposed(ExtensionType.PASSWORD_SALT));
        assertArrayEquals(new byte[32], context.getServerPWDSalt());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof PasswordSaltExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new PasswordSaltExtensionMessage()) instanceof PasswordSaltExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new PasswordSaltExtensionMessage()) instanceof PasswordSaltExtensionSerializer);
    }

}