/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParserTest;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class KeyShareExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return KeyShareExtensionParserTest.generateData();
    }

    private byte[] extension;
    private int keyShareListLength;
    private byte[] keyShareList;

    public KeyShareExtensionSerializerTest(byte[] extension, int keyShareListLength, byte[] keyShareList) {
        this.extension = extension;
        this.keyShareListLength = keyShareListLength;
        this.keyShareList = keyShareList;
    }

    /**
     * Test of serializeExtensionContent method, of class KeyShareExtensionSerializerTest.
     */
    @Test
    public void testSerializeExtensionContent() {
        KeyShareExtensionMessage msg = new KeyShareExtensionMessage();
        msg.setKeyShareListBytes(keyShareList);
        msg.setKeyShareListLength(keyShareListLength);
        KeyShareExtensionSerializer serializer = new KeyShareExtensionSerializer(msg, ConnectionEndType.CLIENT);
        assertArrayEquals(extension, serializer.serializeExtensionContent());
    }

}
