/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateStatusRequestExtensionParserTest {
    /**
     * Parameterized set up of the test vector.
     *
     * @return test vector (extensionType, extensionLength, extensionPayload,
     *         expectedBytes)
     */
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
                { ExtensionType.STATUS_REQUEST, ArrayConverter.hexStringToByteArray("000500050100000000"), 5, 0, 1, 0,
                        new byte[0], 0, new byte[0] },
                { ExtensionType.STATUS_REQUEST, ArrayConverter.hexStringToByteArray("0005000701000102000103"), 7, 0, 1,
                        1, new byte[] { 0x02 }, 1, new byte[] { 0x03 } } });
    }

    private final ExtensionType extensionType;
    private final byte[] expectedBytes;
    private final int extensionLength;
    private final int startParsing;
    private final int certificateStatusRequestType;
    private final int responderIDListLength;
    private final byte[] responderIDList;
    private final int requestExtensionLength;
    private final byte[] requestExtension;
    private CertificateStatusRequestExtensionParser parser;
    private CertificateStatusRequestExtensionMessage message;

    public CertificateStatusRequestExtensionParserTest(ExtensionType extensionType, byte[] expectedBytes,
            int extensionLength, int startParsing, int certificateStatusRequestType, int responderIDListLength,
            byte[] responderIDList, int requestExtensionLength, byte[] requestExtension) {
        this.extensionType = extensionType;
        this.expectedBytes = expectedBytes;
        this.extensionLength = extensionLength;
        this.startParsing = startParsing;
        this.certificateStatusRequestType = certificateStatusRequestType;
        this.responderIDListLength = responderIDListLength;
        this.responderIDList = responderIDList;
        this.requestExtensionLength = requestExtensionLength;
        this.requestExtension = requestExtension;
    }

    @Before
    public void setUp() {
        parser = new CertificateStatusRequestExtensionParser(startParsing, expectedBytes);
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();

        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());

        assertEquals(certificateStatusRequestType, (long) message.getCertificateStatusRequestType().getValue());

        assertEquals(responderIDListLength, (long) message.getResponderIDListLength().getValue());
        assertArrayEquals(responderIDList, message.getResponderIDList().getValue());

        assertEquals(requestExtensionLength, (long) message.getRequestExtensionLength().getValue());
        assertArrayEquals(requestExtension, message.getRequestExtension().getValue());
    }
}
