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
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.HRRKeyShareExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HRRKeyShareExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return HRRKeyShareExtensionParserTest.generateData();
    }

    private byte[] extension;
    private int start;
    private byte[] completeExtension;
    private ExtensionType type;
    private int extensionLength;
    private byte[] selectedGroup;

    public HRRKeyShareExtensionSerializerTest(byte[] extension, int start, byte[] completeExtension,
            ExtensionType type, int extensionLength, byte[] selectedGroup) {
        this.extension = extension;
        this.start = start;
        this.completeExtension = completeExtension;
        this.type = type;
        this.extensionLength = extensionLength;
        this.selectedGroup = selectedGroup;
    }

    /**
     * Test of serializeExtensionContent method, of class
     * HRRKeyShareExtensionSerializer.
     */
    @Test
    public void testSerializeExtensionContent() {
        HRRKeyShareExtensionMessage msg = new HRRKeyShareExtensionMessage();
        msg.setExtensionType(type.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setSelectedGroup(selectedGroup);
        HRRKeyShareExtensionSerializer serializer = new HRRKeyShareExtensionSerializer(msg);
        assertArrayEquals(completeExtension, serializer.serialize());
    }

}