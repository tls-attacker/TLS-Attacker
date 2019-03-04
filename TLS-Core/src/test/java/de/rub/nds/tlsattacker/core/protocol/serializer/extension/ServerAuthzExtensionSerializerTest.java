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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientAuthzExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ServerAuthzExtensionSerializerTest {
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ClientAuthzExtensionParserTest.generateData();
    }

    private final ExtensionType extensionType;
    private final byte[] expectedBytes;
    private final int extensionLength;
    private final int authzFormatListLength;
    private final byte[] authzFormatList;
    private ServerAuthzExtensionMessage msg;
    private ServerAuthzExtensionSerializer serializer;

    public ServerAuthzExtensionSerializerTest(ExtensionType extensionType, byte[] expectedBytes, int extensionLength,
            int startParsing, int authzFormatListLength, byte[] authzFormatList) {
        this.extensionType = extensionType;
        this.expectedBytes = expectedBytes;
        this.extensionLength = extensionLength;
        this.authzFormatListLength = authzFormatListLength;
        this.authzFormatList = authzFormatList;
    }

    @Test
    public void testSerializeExtensionContent() {
        msg = new ServerAuthzExtensionMessage();
        serializer = new ServerAuthzExtensionSerializer(msg);

        msg.setExtensionType(extensionType.getValue());
        msg.setExtensionLength(extensionLength);
        msg.setAuthzFormatListLength(authzFormatListLength);
        msg.setAuthzFormatList(authzFormatList);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
