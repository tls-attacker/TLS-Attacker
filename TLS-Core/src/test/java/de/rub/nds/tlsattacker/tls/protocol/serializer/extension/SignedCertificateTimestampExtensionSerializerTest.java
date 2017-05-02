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
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.SignedCertificateTimestampExtensionHandlerTest;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import java.util.Collection;
import org.junit.Assert;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class SignedCertificateTimestampExtensionSerializerTest extends ExtensionSerializerTest {
    private final ExtensionType extensionType;
    private final int lengthFirstPackage;
    private final byte[] firstTimestamp;
    private final byte[] firstExpectedBytes;
    private final byte[] secondTimestamp;
    private final byte[] secondExpectedBytes;
    private final int lengthSecondPackage;
    private final int startPosition;

    public SignedCertificateTimestampExtensionSerializerTest(ExtensionType extensionType, int lengthFirstPackage,
            byte[] firstTimestamp, byte[] firstExpectedBytes, byte[] secondTimestamp, byte[] secondExpectedBytes,
            int lengthSecondPackage, int startPosition) {
        this.extensionType = extensionType;
        this.lengthFirstPackage = lengthFirstPackage;
        this.firstTimestamp = firstTimestamp;
        this.firstExpectedBytes = firstExpectedBytes;
        this.secondTimestamp = secondTimestamp;
        this.secondExpectedBytes = secondExpectedBytes;
        this.lengthSecondPackage = lengthSecondPackage;
        this.startPosition = startPosition;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SignedCertificateTimestampExtensionHandlerTest.generateData();
    }

    @Test
    @Override
    public void testSerializeExtensionContent() {
        message = new SignedCertificateTimestampExtensionMessage();
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(lengthFirstPackage);
        ((SignedCertificateTimestampExtensionMessage) message).setSignedTimestamp(firstTimestamp);

        SignedCertificateTimestampExtensionSerializer serializer = new SignedCertificateTimestampExtensionSerializer(
                (SignedCertificateTimestampExtensionMessage) message);
        assertArrayEquals(firstExpectedBytes, serializer.serialize());

        message.setExtensionLength(lengthSecondPackage);
        ((SignedCertificateTimestampExtensionMessage) message).setSignedTimestamp(secondTimestamp);
        assertArrayEquals(secondExpectedBytes, serializer.serialize());

    }
}
