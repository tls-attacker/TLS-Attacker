/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.PaddingExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PaddingExtensionSerializerTest {

    /**
     * Parameterized set up of the test vector.
     *
     * @return test vector (extensionType, extensionLength, extensionPayload, expectedBytes)
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return PaddingExtensionParserTest.generateData();
    }

    private final byte[] extensionPayload;
    private final byte[] expectedBytes;
    private PaddingExtensionMessage message;

    public PaddingExtensionSerializerTest(byte[] extensionPayload, byte[] expectedBytes) {
        this.extensionPayload = extensionPayload;
        this.expectedBytes = expectedBytes;
    }

    /**
     * Tests the serializer of the padding extension.
     */
    @Test
    public void testSerializeExtensionContent() {
        message = new PaddingExtensionMessage();
        message.setPaddingBytes(extensionPayload);

        PaddingExtensionSerializer serializer = new PaddingExtensionSerializer(message);

        assertArrayEquals(expectedBytes, serializer.serializeExtensionContent());

    }

}
