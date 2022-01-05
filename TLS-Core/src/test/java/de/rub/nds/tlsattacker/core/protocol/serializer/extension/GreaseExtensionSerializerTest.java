/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.GreaseExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class GreaseExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return GreaseExtensionParserTest.generateData();
    }

    private final byte[] extension;
    private final byte[] randomData;

    public GreaseExtensionSerializerTest(byte[] extension, byte[] randomData) {
        this.extension = extension;
        this.randomData = randomData;
    }

    /**
     * Test of serializeExtensionContent method, of class KeyShareExtensionSerializerTest.
     */
    @Test
    public void testSerializeExtensionContent() {
        GreaseExtensionMessage msg = new GreaseExtensionMessage();
        msg.setRandomData(randomData);
        GreaseExtensionSerializer serializer = new GreaseExtensionSerializer(msg);
        assertArrayEquals(extension, serializer.serializeExtensionContent());
    }
}
