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
import de.rub.nds.tlsattacker.core.protocol.handler.extension.TokenBindingExtensionHandlerTest;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class TokenBindingExtensionParserTest extends ExtensionParserTest {

    private final ExtensionType extensionType;
    private final byte[] extensionBytes;
    private final int extensionLength;
    private final TokenBindingVersion majorVersion;
    private final TokenBindingVersion minorVersion;
    private final int parameterLength;
    private final byte[] keyParameter;

    public TokenBindingExtensionParserTest(ExtensionType extensionType, byte[] extensionBytes, int extensionLength,
            TokenBindingVersion majorVersion, TokenBindingVersion minorVersion, int parameterLength, byte[] keyParameter) {
        this.extensionType = extensionType;
        this.extensionBytes = extensionBytes;
        this.extensionLength = extensionLength;
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
        this.parameterLength = parameterLength;
        this.keyParameter = keyParameter;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ExtensionType.TOKEN_BINDING,
                new byte[] { 0x00, 0x18, 0x00, 0x04, 0x00, 0x0d, 0x01, 0x02 }, 4, TokenBindingVersion.ZERO_BYTE,
                TokenBindingVersion.DRAFT_13, 1,
                new byte[] { TokenBindingKeyParameters.ECDSAP256.getKeyParameterValue() } } });
    }

    @Before
    @Override
    public void setUp() {
        parser = new TokenBindingExtensionParser(0, extensionBytes);
        message = parser.parse();
    }

    @Test
    @Override
    public void testParseExtensionMessageContent() {
        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(majorVersion.getByteValue(), (byte) ((TokenBindingExtensionMessage) message).getMajorTokenbindingVersion().getValue());
        assertEquals(minorVersion.getByteValue(), (byte) ((TokenBindingExtensionMessage) message).getMinorTokenbindingVersion().getValue());
        assertEquals(parameterLength, ((TokenBindingExtensionMessage) message).getParameterListLength());
        assertArrayEquals(keyParameter, ((TokenBindingExtensionMessage) message).getTokenbindingKeyParameters().getValue());
    }

}
