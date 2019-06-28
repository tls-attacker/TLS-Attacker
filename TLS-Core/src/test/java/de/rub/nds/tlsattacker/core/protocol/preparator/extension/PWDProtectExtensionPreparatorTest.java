/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDProtectExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PWDProtectExtensionPreparatorTest {

    private TlsContext context;
    private PWDProtectExtensionMessage message;
    private PWDProtectExtensionPreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new PWDProtectExtensionMessage();
        preparator = new PWDProtectExtensionPreparator(context.getChooser(), message,
                new PWDProtectExtensionSerializer(message));
    }

    @Test
    public void testPreparator() {
        context.setClientPWDUsername("jens");
        preparator.prepare();
        byte[] encryptedUsername = ArrayConverter
                .hexStringToByteArray("DA87739AC04C2A6D222FC15E31C471451DE3FE7E78B6E3485CA21E12BFE1CB4C4191D4CD9257145CBFA26DFCA1839C1588D0F1F6");
        assertArrayEquals(ExtensionType.PWD_PROTECT.getValue(), message.getExtensionType().getValue());
        assertArrayEquals(encryptedUsername, message.getUsername().getValue());
        assertEquals(52 + 1, (long) message.getExtensionLength().getValue());

    }

}