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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;

public class ClientCertificateUrlExtensionSerializerTest {
    private final ExtensionType extensionType = ExtensionType.CLIENT_CERTIFICATE_URL;
    private final byte[] expectedBytes = new byte[] { 0x00, 0x02, 0x00, 0x00 };
    private final int extensionLength = 0;
    private ClientCertificateUrlExtensionMessage message;
    private ClientCertificateUrlExtensionSerializer serializer;

    @Before
    public void setUp() {
        message = new ClientCertificateUrlExtensionMessage();
        serializer = new ClientCertificateUrlExtensionSerializer(message);
    }

    @Test
    public void testSerializeExtensionContent() {
        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
