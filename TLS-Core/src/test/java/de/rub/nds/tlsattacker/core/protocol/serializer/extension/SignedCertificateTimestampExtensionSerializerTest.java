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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignedCertificateTimestampExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SignedCertificateTimestampExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SignedCertificateTimestampExtensionParserTest.generateData();
    }

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] timestamp;
    private final byte[] expectedBytes;
    private SignedCertificateTimestampExtensionMessage message;

    public SignedCertificateTimestampExtensionSerializerTest(ExtensionType extensionType, int extensionLength,
            byte[] timestamp, byte[] expectedBytes, int startPosition) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.timestamp = timestamp;
        this.expectedBytes = expectedBytes;
    }

    @Test
    public void testSerializeExtensionContent() {
        message = new SignedCertificateTimestampExtensionMessage();
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);
        message.setSignedTimestamp(timestamp);

        SignedCertificateTimestampExtensionSerializer serializer = new SignedCertificateTimestampExtensionSerializer(
                message);
        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
