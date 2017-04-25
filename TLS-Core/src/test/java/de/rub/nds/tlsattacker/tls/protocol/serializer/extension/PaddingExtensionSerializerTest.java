/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.PaddingExtensionMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class PaddingExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][]{{ExtensionType.PADDING, 6,
            new byte[]{0, 0, 0, 0, 0, 0},
            ArrayConverter.hexStringToByteArray("00150006000000000000")}});
    }

    private ExtensionType extensionType;
    private int extensionLength;
    private byte[] extensionPayload;
    private byte[] expectedBytes;

    public PaddingExtensionSerializerTest(ExtensionType extensionType, int extensionLength, byte[] extensionPayload, byte[] expectedBytes) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.extensionPayload = extensionPayload;
        this.expectedBytes = expectedBytes;
    }

    @Test
    public void testSerializeExtensionContent() {
        // 00 15 00 06 0 0 0 0 0 0 base 16
        PaddingExtensionMessage msg = new PaddingExtensionMessage();
        msg.setExtensionType(extensionType.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setPaddingLength(extensionLength);
        msg.setPaddingBytes(extensionPayload);
        PaddingExtensionSerializer serializer = new PaddingExtensionSerializer(msg);
        byte[] test = serializer.serialize();
        assertArrayEquals(expectedBytes, test);

    }

}
