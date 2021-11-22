/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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

    private final byte[] extension;
    private final int versionListLength;
    private final byte[] versionList;

    public SupportedVersionsExtensionSerializerTest(byte[] extension, int versionListLength, byte[] versionList) {
        this.extension = extension;
        this.versionListLength = versionListLength;
        this.versionList = versionList;
    }

    /**
     * Test of serializeExtensionContent method, of class SupportedVersionsExtensionSerializer.
     */
    @Test
    public void testSerializeExtensionContent() {
        SupportedVersionsExtensionMessage msg = new SupportedVersionsExtensionMessage();
        msg.setSupportedVersions(versionList);
        msg.setSupportedVersionsLength(versionListLength);
        SupportedVersionsExtensionSerializer serializer = new SupportedVersionsExtensionSerializer(msg);
        assertArrayEquals(extension, serializer.serializeExtensionContent());
    }
}
