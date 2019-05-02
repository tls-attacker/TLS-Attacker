package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDClearExtensionMessage;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class PWDClearExtensionSerializerTest {
    private final ExtensionType extensionType = ExtensionType.PWD_CLEAR;
    private final byte[] expectedBytes = new byte[] { 0x00, 0x1e, 0x00, 0x05, 0x04, 0x66, 0x72, 0x65, 0x64 };
    private final int extensionLength = 5;
    private PWDClearExtensionMessage message;
    private PWDClearExtensionSerializer serializer;

    @Before
    public void setUp() {
        message = new PWDClearExtensionMessage();
        serializer = new PWDClearExtensionSerializer(message);
    }

    @Test
    public void testSerializeExtensionContent() {
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);
        message.setUsername("fred");
        message.setUsernameLength(4);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }

}