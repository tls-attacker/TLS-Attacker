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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PaddingExtensionSerializer;
import org.junit.jupiter.api.Test;

public class PaddingExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                PaddingExtensionMessage, PaddingExtensionSerializer, PaddingExtensionPreparator> {

    public PaddingExtensionPreparatorTest() {
        super(
                PaddingExtensionMessage::new,
                PaddingExtensionSerializer::new,
                PaddingExtensionPreparator::new);
    }

    /** Tests the preparator of the padding extension message. */
    @Test
    @Override
    public void testPrepare() {
        byte[] extensionPayload = new byte[] {0, 0, 0, 0, 0, 0};
        context.getConfig().setDefaultPaddingExtensionBytes(extensionPayload);
        preparator.prepare();

        assertArrayEquals(ExtensionType.PADDING.getValue(), message.getExtensionType().getValue());
        assertEquals(6, message.getExtensionLength().getValue());
        assertArrayEquals(extensionPayload, message.getPaddingBytes().getValue());
    }
}
