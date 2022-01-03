/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TokenBindingExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class TokenBindingExtensionSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return TokenBindingExtensionParserTest.generateData();
    }

    private final byte[] extensionBytes;
    private final TokenBindingVersion tokenbindingVersion;
    private final int parameterLength;
    private final byte[] keyParameter;
    private TokenBindingExtensionMessage message;

    public TokenBindingExtensionSerializerTest(byte[] extensionBytes, TokenBindingVersion tokenbindingVersion,
        int parameterLength, byte[] keyParameter) {
        this.extensionBytes = extensionBytes;
        this.tokenbindingVersion = tokenbindingVersion;
        this.parameterLength = parameterLength;
        this.keyParameter = keyParameter;
    }

    @Test
    public void testSerializeExtensionContent() {
        message = new TokenBindingExtensionMessage();
        message.setTokenbindingVersion(tokenbindingVersion.getByteValue());
        message.setParameterListLength(parameterLength);
        message.setTokenbindingKeyParameters(keyParameter);

        TokenBindingExtensionSerializer serializer = new TokenBindingExtensionSerializer(message);

        assertArrayEquals(extensionBytes, serializer.serializeExtensionContent());

    }

}
