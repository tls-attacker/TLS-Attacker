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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SupportedVersionsExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SupportedVersionsExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SupportedVersionsExtensionParserTest.generateData();
    }

    private final byte[] completeExtension;
    private final ExtensionType type;
    private final int extensionLength;
    private final int versionListLength;
    private final byte[] versionList;

    public SupportedVersionsExtensionSerializerTest(byte[] extension, int start, byte[] completeExtension,
            ExtensionType type, int extensionLength, int versionListLength, byte[] versionList) {
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.versionListLength = versionListLength;
        this.versionList = versionList;
    }

    /**
     * Test of serializeExtensionContent method, of class
     * SupportedVersionsExtensionSerializer.
     */
    @Test
    public void testSerializeExtensionContent() {
        SupportedVersionsExtensionMessage msg = new SupportedVersionsExtensionMessage();
        msg.setExtensionType(type.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setSupportedVersions(versionList);
        msg.setSupportedVersionsLength(versionListLength);
        SupportedVersionsExtensionSerializer serializer = new SupportedVersionsExtensionSerializer(msg);
        assertArrayEquals(completeExtension, serializer.serialize());
    }
}
