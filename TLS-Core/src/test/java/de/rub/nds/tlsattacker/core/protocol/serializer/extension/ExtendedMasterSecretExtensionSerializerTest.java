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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtendedMasterSecretExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ExtendedMasterSecretExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ExtendedMasterSecretExtensionParserTest.generateData();
    }

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] expectedBytes;
    private ExtendedMasterSecretExtensionMessage message;

    public ExtendedMasterSecretExtensionSerializerTest(ExtensionType extensionType, int extensionLength,
            byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.expectedBytes = expectedBytes;
    }

    @Test
    public void testSerializeExtensionContent() {
        message = new ExtendedMasterSecretExtensionMessage();
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);

        ExtendedMasterSecretExtensionSerializer serializer = new ExtendedMasterSecretExtensionSerializer(message);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
