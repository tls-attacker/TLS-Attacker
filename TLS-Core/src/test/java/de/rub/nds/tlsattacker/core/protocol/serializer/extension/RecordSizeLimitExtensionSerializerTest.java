/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class RecordSizeLimitExtensionSerializerTest {

    private RecordSizeLimitExtensionSerializer serializer;
    private RecordSizeLimitExtensionMessage message;

    @Before
    public void setUp() {
    }

    /**
     * Test of serializeExtensionContent method of class RecordSizeLimitExtensionSerializer.
     */
    @Test
    public void testSerializeBytes() {
        message = new RecordSizeLimitExtensionMessage();
        message.setExtensionType(ExtensionType.RECORD_SIZE_LIMIT.getValue());
        message.setExtensionLength(ExtensionByteLength.RECORD_SIZE_LIMIT_LENGTH);
        message.setRecordSizeLimit(new byte[] { 0x20, 0x00 });
        serializer = new RecordSizeLimitExtensionSerializer(message);
        byte[] result = serializer.serialize();
        assertArrayEquals(ArrayConverter.hexStringToByteArray("001C00022000"), result);
    }
}
