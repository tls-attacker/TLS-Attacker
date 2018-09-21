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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class CertificateStatusRequestExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return CertificateStatusRequestExtensionParserTest.generateData();
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
    private CertificateStatusRequestExtensionMessage message;
    private CertificateStatusRequestExtensionSerializer serializer;

    public CertificateStatusRequestExtensionSerializerTest(ExtensionType extensionType, byte[] expectedBytes,
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
        message = new CertificateStatusRequestExtensionMessage();
        serializer = new CertificateStatusRequestExtensionSerializer(message);
    }

    @Test
    public void testSerializeExtensionContent() {

        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);

        message.setCertificateStatusRequestType(certificateStatusRequestType);

        message.setResponderIDListLength(responderIDListLength);
        message.setResponderIDList(responderIDList);

        message.setRequestExtensionLength(requestExtensionLength);
        message.setRequestExtension(requestExtension);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }

}
