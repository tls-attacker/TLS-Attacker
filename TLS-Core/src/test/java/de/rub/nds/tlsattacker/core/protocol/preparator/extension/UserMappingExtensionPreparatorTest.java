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

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.UserMappingExtensionHintType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.UserMappingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.UserMappingExtensionSerializer;
import org.junit.jupiter.api.Test;

public class UserMappingExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                UserMappingExtensionMessage,
                UserMappingExtensionSerializer,
                UserMappingExtensionPreparator> {

    public UserMappingExtensionPreparatorTest() {
        super(
                UserMappingExtensionMessage::new,
                UserMappingExtensionSerializer::new,
                UserMappingExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        context.getConfig()
                .setUserMappingExtensionHintType(UserMappingExtensionHintType.UPN_DOMAIN_HINT);

        preparator.prepare();

        assertArrayEquals(
                ExtensionType.USER_MAPPING.getValue(), message.getExtensionType().getValue());
        assertEquals(1, message.getExtensionLength().getValue());
        assertEquals(
                UserMappingExtensionHintType.UPN_DOMAIN_HINT.getValue(),
                message.getUserMappingType().getValue());
    }
}
