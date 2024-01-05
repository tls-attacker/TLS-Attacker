/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDProtectExtensionSerializer;
import org.junit.jupiter.api.Test;

public class PWDProtectExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                PWDProtectExtensionMessage,
                PWDProtectExtensionSerializer,
                PWDProtectExtensionPreparator> {

    public PWDProtectExtensionPreparatorTest() {
        super(
                PWDProtectExtensionMessage::new,
                PWDProtectExtensionSerializer::new,
                PWDProtectExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        context.setClientPWDUsername("jens");
        preparator.prepare();
        byte[] encryptedUsername =
                ArrayConverter.hexStringToByteArray(
                        "DA87739AC04C2A6D222FC15E31C471451DE3FE7E78B6E3485CA21E12BFE1CB4C4191D4CD9257145CBFA26DFCA1839C1588D0F1F6");
        assertArrayEquals(
                ExtensionType.PWD_PROTECT.getValue(), message.getExtensionType().getValue());
        assertArrayEquals(encryptedUsername, message.getUsername().getValue());
        assertEquals(53, message.getExtensionLength().getValue());
    }
}
