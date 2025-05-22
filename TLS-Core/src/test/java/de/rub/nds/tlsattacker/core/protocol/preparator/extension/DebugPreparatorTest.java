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
import de.rub.nds.tlsattacker.core.protocol.message.extension.DebugExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.DebugExtensionSerializer;
import org.junit.jupiter.api.Test;

public class DebugPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                DebugExtensionMessage, DebugExtensionSerializer, DebugExtensionPreparator> {

    public DebugPreparatorTest() {
        super(
                DebugExtensionMessage::new,
                DebugExtensionSerializer::new,
                DebugExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        context.getConfig().setDefaultDebugContent("NEW DEBUG MESSAGE");
        ;
        preparator.prepare();

        assertArrayEquals(ExtensionType.DEBUG.getValue(), message.getExtensionType().getValue());
        assertEquals(
                context.getConfig().getDefaultDebugContent(), message.getDebugContent().getValue());
    }
}
