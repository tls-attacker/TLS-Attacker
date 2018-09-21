/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientCertificateTypeExtensionParserTest;
import java.util.Collection;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ClientCertificateTypeExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ClientCertificateTypeExtensionParserTest.generateData();
    }

    private final ExtensionType extensionType;
    private final byte[] expectedBytes;
    private final int extensionLength;
    private final int startParsing;
    private final Integer certificateTypesLength;
    private final List<CertificateType> certificateTypes;
    private final boolean isClientState;
    private ClientCertificateTypeExtensionSerializer serializer;
    private ClientCertificateTypeExtensionMessage msg;

    public ClientCertificateTypeExtensionSerializerTest(ExtensionType extensionType, byte[] expectedBytes,
            int extensionLength, int startParsing, Integer certificateTypesLength,
            List<CertificateType> certificateTypes, boolean isClientState) {
        this.extensionType = extensionType;
        this.expectedBytes = expectedBytes;
        this.extensionLength = extensionLength;
        this.startParsing = startParsing;
        this.certificateTypesLength = certificateTypesLength;
        this.certificateTypes = certificateTypes;
        this.isClientState = isClientState;
    }

    @Before
    public void setUp() {
        msg = new ClientCertificateTypeExtensionMessage();
        serializer = new ClientCertificateTypeExtensionSerializer(msg);
    }

    @Test
    public void testSerializeExtensionContent() {
        msg.setExtensionType(extensionType.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setCertificateTypes(CertificateType.toByteArray(certificateTypes));
        if (certificateTypesLength != null) {
            msg.setCertificateTypesLength(certificateTypesLength);
        } else {
            msg.setCertificateTypesLength(null);
        }
        msg.setIsClientMessage(isClientState);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
