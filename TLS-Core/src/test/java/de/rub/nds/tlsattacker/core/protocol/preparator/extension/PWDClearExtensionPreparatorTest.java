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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDClearExtensionSerializer;
import org.junit.jupiter.api.Test;

public class PWDClearExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                PWDClearExtensionMessage,
                PWDClearExtensionSerializer,
                PWDClearExtensionPreparator> {

    public PWDClearExtensionPreparatorTest() {
        super(
                PWDClearExtensionMessage::new,
                PWDClearExtensionSerializer::new,
                PWDClearExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        context.setClientPWDUsername("Bob");
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.PWD_CLEAR.getValue(), message.getExtensionType().getValue());
        assertEquals(3 + 1, (long) message.getExtensionLength().getValue());
    }
}
