/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.KeyShareExtensionParserTest;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class KeyShareExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return KeyShareExtensionParserTest.generateData();
    }

    private byte[] extension;
    private int start;
    private byte[] completeExtension;
    private ExtensionType type;
    private int extensionLength;
    private int keyShareListLength;
    private byte[] keyShareList;

    public KeyShareExtensionSerializerTest(byte[] extension, int start, byte[] completeExtension, ExtensionType type,
            int extensionLength, int keyShareListLength, byte[] keyShareList) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.keyShareListLength = keyShareListLength;
        this.keyShareList = keyShareList;
    }

    /**
     * Test of serializeExtensionContent method, of class
     * KeyShareExtensionSerializerTest.
     */
    @Test
    public void testSerializeExtensionContent() {
        KeyShareExtensionMessage msg = new KeyShareExtensionMessage();
        msg.setExtensionType(type.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setKeyShareListBytes(keyShareList);
        msg.setKeyShareListLength(keyShareListLength);
        KeyShareExtensionSerializer serializer = new KeyShareExtensionSerializer(msg, ConnectionEndType.CLIENT);
        assertArrayEquals(completeExtension, serializer.serialize());
    }

}
