/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializerTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class ExtendedMasterSecretExtensionParserTest extends ExtensionParserTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] expectedBytes;
    private final int startParsing;

    public ExtendedMasterSecretExtensionParserTest(ExtensionType extensionType, int extensionLength, byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ExtendedMasterSecretExtensionSerializerTest.generateData();
    }

    @Test
    @Override
    public void testParseExtensionMessageContent() {

        parser = new ExtendedMasterSecretExtensionParser(startParsing, expectedBytes);
        message = parser.parse();

        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (int) message.getExtensionLength().getValue());
    }

}
