/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignedCertificateTimestampExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignedCertificateTimestampExtensionParserTest;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignedCertificateTimestampExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignedCertificateTimestampExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class SignedCertificateTimestampExtensionHandlerTest {

    private final ExtensionType extensionType;
    private final int lengthFirstPackage;
    private final byte[] firstTimestamp;
    private final byte[] firstExpectedBytes;
    private final byte[] secondTimestamp;
    private final byte[] secondExpectedBytes;
    private final int lengthSecondPackage;
    private final int startPosition;
    private TlsContext context;
    private SignedCertificateTimestampExtensionHandler handler;

    public SignedCertificateTimestampExtensionHandlerTest(ExtensionType extensionType, int lengthFirstPackage,
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

    // The secont byte array is a timestamp as found in a ServerHello message.
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SignedCertificateTimestampExtensionParserTest.generateData();
    }

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new SignedCertificateTimestampExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        SignedCertificateTimestampExtensionMessage messageOne = new SignedCertificateTimestampExtensionMessage();
        messageOne.setSignedTimestamp(firstTimestamp);
        messageOne.setExtensionLength(lengthFirstPackage);

        handler.adjustTLSContext(messageOne);
        assertArrayEquals(firstTimestamp, context.getSignedCertificateTimestamp());

        SignedCertificateTimestampExtensionMessage messageTwo = new SignedCertificateTimestampExtensionMessage();
        messageTwo.setSignedTimestamp(secondTimestamp);
        messageTwo.setExtensionLength(lengthSecondPackage);
        handler.adjustTLSContext(messageTwo);

        assertArrayEquals(secondTimestamp, context.getSignedCertificateTimestamp());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(firstExpectedBytes, startPosition) instanceof SignedCertificateTimestampExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new SignedCertificateTimestampExtensionMessage()) instanceof SignedCertificateTimestampExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new SignedCertificateTimestampExtensionMessage()) instanceof SignedCertificateTimestampExtensionSerializer);
    }
}
