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
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.UserMappingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.UserMappingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.UserMappingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UserMappingExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class UserMappingExtensionHandlerTest {
    private final UserMappingExtensionHintType hintType = UserMappingExtensionHintType.UPN_DOMAIN_HINT;
    private UserMappingExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new UserMappingExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        UserMappingExtensionMessage msg = new UserMappingExtensionMessage();
        msg.setUserMappingType(hintType.getValue());
        handler.adjustTLSContext(msg);
        assertTrue(context.isExtensionProposed(ExtensionType.USER_MAPPING));
        assertEquals(hintType.getValue(), context.getUserMappingExtensionHintType().getValue());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof UserMappingExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new UserMappingExtensionMessage()) instanceof UserMappingExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new UserMappingExtensionMessage()) instanceof UserMappingExtensionSerializer);
    }
}
