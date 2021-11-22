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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SRPExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SRPExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SRPExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return SRPExtensionParserTest.generateData();
    }

    private final byte[] extensionBytes;
    private final int srpIdentifierLength;
    private final byte[] srpIdentifier;
    private SRPExtensionSerializer serializer;
    private SRPExtensionMessage message;

    public SRPExtensionSerializerTest(byte[] extensionBytes, int srpIdentifierLength, byte[] srpIdentifier) {
        this.extensionBytes = extensionBytes;
        this.srpIdentifierLength = srpIdentifierLength;
        this.srpIdentifier = srpIdentifier;
    }

    @Before
    public void setUp() {
        message = new SRPExtensionMessage();
        serializer = new SRPExtensionSerializer(message);
    }

    @Test
    public void testSerializeExtensionContent() {
        message.setSrpIdentifierLength(srpIdentifierLength);
        message.setSrpIdentifier(srpIdentifier);

        assertArrayEquals(extensionBytes, serializer.serializeExtensionContent());
    }

}
