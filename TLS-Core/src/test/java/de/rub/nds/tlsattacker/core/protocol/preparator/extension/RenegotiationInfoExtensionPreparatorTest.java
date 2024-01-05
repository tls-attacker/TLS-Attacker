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
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RenegotiationInfoExtensionSerializer;
import org.junit.jupiter.api.Test;

public class RenegotiationInfoExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                RenegotiationInfoExtensionMessage,
                RenegotiationInfoExtensionSerializer,
                RenegotiationInfoExtensionPreparator> {

    public RenegotiationInfoExtensionPreparatorTest() {
        super(
                RenegotiationInfoExtensionMessage::new,
                RenegotiationInfoExtensionSerializer::new,
                RenegotiationInfoExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        byte[] extensionPayload = new byte[] {0};
        context.getConfig().setDefaultClientRenegotiationInfo(extensionPayload);
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.RENEGOTIATION_INFO.getValue(), message.getExtensionType().getValue());
        assertEquals(2, (long) message.getExtensionLength().getValue());
        assertArrayEquals(extensionPayload, message.getRenegotiationInfo().getValue());
        assertEquals(1, (long) message.getRenegotiationInfoLength().getValue());
    }
}
