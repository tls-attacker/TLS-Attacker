/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientAuthzExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ClientAuthzExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ClientAuthzExtensionParserTest.generateData();
    }

    private final byte[] expectedBytes;
    private final int authzFormatListLength;
    private final byte[] authzFormatList;
    private ClientAuthzExtensionMessage msg;
    private ClientAuthzExtensionSerializer serializer;

    public ClientAuthzExtensionSerializerTest(byte[] expectedBytes, int authzFormatListLength, byte[] authzFormatList) {
        this.expectedBytes = expectedBytes;
        this.authzFormatListLength = authzFormatListLength;
        this.authzFormatList = authzFormatList;
    }

    @Test
    public void testSerializeExtensionContent() {
        msg = new ClientAuthzExtensionMessage();
        serializer = new ClientAuthzExtensionSerializer(msg);
        msg.setAuthzFormatListLength(authzFormatListLength);
        msg.setAuthzFormatList(authzFormatList);

        assertArrayEquals(expectedBytes, serializer.serializeExtensionContent());
    }
}
