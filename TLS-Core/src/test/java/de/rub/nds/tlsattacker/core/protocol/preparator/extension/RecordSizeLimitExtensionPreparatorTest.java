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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RecordSizeLimitExtensionSerializer;
import org.junit.jupiter.api.Test;

public class RecordSizeLimitExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                RecordSizeLimitExtensionMessage,
                RecordSizeLimitExtensionSerializer,
                RecordSizeLimitExtensionPreparator> {

    public RecordSizeLimitExtensionPreparatorTest() {
        super(
                RecordSizeLimitExtensionMessage::new,
                RecordSizeLimitExtensionSerializer::new,
                RecordSizeLimitExtensionPreparator::new);
    }

    /** Test of prepare method, of class RecordSizeLimitExtensionPreparator. */
    @Test
    @Override
    public void testPrepare() {
        context.getConfig().setInboundRecordSizeLimit(1337);

        preparator.prepare();

        assertArrayEquals(
                new byte[] {(byte) 0x05, (byte) 0x39}, message.getRecordSizeLimit().getValue());
        assertArrayEquals(
                ArrayConverter.intToBytes(context.getConfig().getInboundRecordSizeLimit(), 2),
                message.getRecordSizeLimit().getValue());
    }
}
