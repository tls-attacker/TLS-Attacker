/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class TokenBindingExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ExtensionType.TOKEN_BINDING,
                new byte[] { 0x00, 0x18, 0x00, 0x04, 0x00, 0x0d, 0x01, 0x02 }, 4, TokenBindingVersion.DRAFT_13, 1,
                new byte[] { TokenBindingKeyParameters.ECDSAP256.getValue() } } });
    }

    private final ExtensionType extensionType;
    private final byte[] extensionBytes;
    private final int extensionLength;
    private final TokenBindingVersion tokenbindingVersion;
    private final int parameterLength;
    private final byte[] keyParameter;
    private TokenBindingExtensionParser parser;
    private TokenBindingExtensionMessage message;

    public TokenBindingExtensionParserTest(ExtensionType extensionType, byte[] extensionBytes, int extensionLength,
            TokenBindingVersion tokenbindingVersion, int parameterLength, byte[] keyParameter) {
        this.extensionType = extensionType;
        this.extensionBytes = extensionBytes;
        this.extensionLength = extensionLength;
        this.tokenbindingVersion = tokenbindingVersion;
        this.parameterLength = parameterLength;
        this.keyParameter = keyParameter;
    }

    @Before
    public void setUp() {
        parser = new TokenBindingExtensionParser(0, extensionBytes);
    }

    @Test
    public void testParseExtensionMessageContent() {
        message = parser.parse();
        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertArrayEquals(tokenbindingVersion.getByteValue(), message.getTokenbindingVersion().getValue());
        assertEquals(parameterLength, (long) message.getParameterListLength().getValue());
        assertArrayEquals(keyParameter, message.getTokenbindingKeyParameters().getValue());
        assertTrue(extensionLength == message.getExtensionLength().getValue());
    }

}
