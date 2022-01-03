/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.GreaseExtensionParserTest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class GreaseExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return GreaseExtensionParserTest.generateData();
    }

    private final byte[] extension;
    private final int start;
    private final byte[] completeExtension;
    private final ExtensionType type;
    private final int extensionLength;
    private final byte[] randomData;

    public GreaseExtensionSerializerTest(byte[] extension, int start, byte[] completeExtension, ExtensionType type,
        int extensionLength, byte[] randomData) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.randomData = randomData;
    }

    /**
     * Test of serializeExtensionContent method, of class KeyShareExtensionSerializerTest.
     */
    @Test
    public void testSerializeExtensionContent() {
        GreaseExtensionMessage msg = new GreaseExtensionMessage();
        msg.setExtensionType(type.getValue());
        msg.setRandomData(randomData);
        msg.setExtensionLength(randomData.length);
        GreaseExtensionSerializer serializer = new GreaseExtensionSerializer(msg);
        assertArrayEquals(completeExtension, serializer.serialize());
    }
}