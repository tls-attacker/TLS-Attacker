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

import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SRPExtensionSerializer;
import org.junit.jupiter.api.Test;

public class SRPExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                SRPExtensionMessage, SRPExtensionSerializer, SRPExtensionPreparator> {

    public SRPExtensionPreparatorTest() {
        super(SRPExtensionMessage::new, SRPExtensionSerializer::new, SRPExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        byte[] srpIdentifier = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04};
        context.getConfig().setSecureRemotePasswordExtensionIdentifier(srpIdentifier);

        preparator.prepare();

        assertArrayEquals(srpIdentifier, message.getSrpIdentifier().getValue());
        assertEquals(5, message.getSrpIdentifierLength().getValue());
    }
}
