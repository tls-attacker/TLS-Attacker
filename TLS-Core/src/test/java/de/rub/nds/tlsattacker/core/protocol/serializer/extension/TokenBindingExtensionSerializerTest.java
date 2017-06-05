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
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TokenBindingExtensionParserTest;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class TokenBindingExtensionSerializerTest extends ExtensionSerializerTest {

    private final ExtensionType extensionType;
    private final byte[] extensionBytes;
    private final int extensionLength;
    private final TokenBindingVersion majorVersion;
    private final TokenBindingVersion minorVersion;
    private final int parameterLength;
    private final byte[] keyParameter;

    public TokenBindingExtensionSerializerTest(ExtensionType extensionType, byte[] extensionBytes, int extensionLength,
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
        return TokenBindingExtensionParserTest.generateData();
    }

    @Test
    @Override
    public void testSerializeExtensionContent() {
        message = new TokenBindingExtensionMessage();

        message.setExtensionType(extensionType.getValue());
        message.setExtensionLength(extensionLength);

        ((TokenBindingExtensionMessage) message).setMajorTokenbindingVersion(majorVersion.getByteValue());
        ((TokenBindingExtensionMessage) message).setMinorTokenbindingVersion(minorVersion.getByteValue());
        ((TokenBindingExtensionMessage) message).setParameterListLength(parameterLength);
        ((TokenBindingExtensionMessage) message).setTokenbindingKeyParameters(keyParameter);

        TokenBindingExtensionSerializer serializer = new TokenBindingExtensionSerializer(
                ((TokenBindingExtensionMessage) message));

        assertArrayEquals(extensionBytes, serializer.serialize());

    }

}
