/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.UserMappingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UserMappingExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class UserMappingExtensionPreparatorTest {
    private static final int EXTENSION_LENGTH = 1;

    private TlsContext context;
    private UserMappingExtensionPreparator preparator;
    private UserMappingExtensionMessage msg;
    private final UserMappingExtensionHintType hintType = UserMappingExtensionHintType.UPN_DOMAIN_HINT;

    @Before
    public void setUp() {
        context = new TlsContext();
        msg = new UserMappingExtensionMessage();
        preparator = new UserMappingExtensionPreparator(context.getChooser(), msg, new UserMappingExtensionSerializer(
                msg));
    }

    @Test
    public void testPreparator() {
        context.getConfig().setUserMappingExtensionHintType(hintType);

        preparator.prepare();

        assertArrayEquals(ExtensionType.USER_MAPPING.getValue(), msg.getExtensionType().getValue());
        assertEquals(EXTENSION_LENGTH, (long) msg.getExtensionLength().getValue());
        assertEquals(hintType.getValue(), (long) msg.getUserMappingType().getValue());
    }
}
