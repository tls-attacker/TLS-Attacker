/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignedCertificateTimestampExtensionHandlerTest;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import java.util.Collection;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class SignedCertificateTimestampExtensionParserTest extends ExtensionParserTest {

    private final ExtensionType extensionType;
    private final int lengthFirstPackage;
    private final byte[] firstTimestamp;
    private final byte[] firstExpectedBytes;
    private final byte[] secondTimestamp;
    private final byte[] secondExpectedBytes;
    private final int lengthSecondPackage;
    private final int startPosition;

    public SignedCertificateTimestampExtensionParserTest(ExtensionType extensionType, int lengthFirstPackage,
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

    @Override
    public void setUp() {
        // Shall be emty, we need the parser two times.
    }

    @Test
    @Override
    public void testParseExtensionMessageContent() {
        // First extension capture
        parser = new SignedCertificateTimestampExtensionParser(startPosition, firstExpectedBytes);
        message = parser.parse();

        assertArrayEquals(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP.getValue(), message.getExtensionType().getValue());
        assertEquals(lengthFirstPackage, (int) message.getExtensionLength().getValue());
        assertArrayEquals(firstTimestamp, ((SignedCertificateTimestampExtensionMessage) message).getSignedTimestamp()
                .getValue());

        // Second extension capture
        parser = new SignedCertificateTimestampExtensionParser(startPosition, secondExpectedBytes);
        message = parser.parse();

        assertArrayEquals(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP.getValue(), message.getExtensionType().getValue());
        assertEquals(lengthSecondPackage, (int) message.getExtensionLength().getValue());
        assertArrayEquals(secondTimestamp, ((SignedCertificateTimestampExtensionMessage) message).getSignedTimestamp()
                .getValue());
    }
}
