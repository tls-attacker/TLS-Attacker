/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
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
public class ExtendedMasterSecretExtensionSerializerTest extends ExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ExtensionType.EXTENDED_MASTER_SECRET, 0,
                ArrayConverter.hexStringToByteArray("00170000"), 0 } });
    }

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] expectedBytes;
    private final int startParsing;

    public ExtendedMasterSecretExtensionSerializerTest(ExtensionType extensionType, int extensionLength,
            byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Override
    @Test
    public void testSerializeExtensionContent() {
        message = new ExtendedMasterSecretExtensionMessage();
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);

        ExtendedMasterSecretExtensionSerializer serializer = new ExtendedMasterSecretExtensionSerializer(
                (ExtendedMasterSecretExtensionMessage) message);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
