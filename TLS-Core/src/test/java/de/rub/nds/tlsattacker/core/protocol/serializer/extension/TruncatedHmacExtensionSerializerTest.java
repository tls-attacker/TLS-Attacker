/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TruncatedHmacExtensionMessage;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class TruncatedHmacExtensionSerializerTest {

    private final byte[] expectedBytes = new byte[0];
    private TruncatedHmacExtensionMessage message;
    private TruncatedHmacExtensionSerializer serializer;

    @Before
    public void setUp() {
        message = new TruncatedHmacExtensionMessage();
        serializer = new TruncatedHmacExtensionSerializer(message);
    }

    @Test
    public void testSerializeExtensionContent() {

        assertArrayEquals(expectedBytes, serializer.serializeExtensionContent());
    }
}
