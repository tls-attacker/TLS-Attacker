/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TokenBindingExtensionParserTest;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.ArrayList;
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
public class TokenBindingExtensionPreparatorTest {

    private final ExtensionType extensionType;
    private final byte[] extensionBytes;
    private final int extensionLength;
    private final TokenBindingVersion majorVersion;
    private final TokenBindingVersion minorVersion;
    private final int parameterLength;
    private final byte[] keyParameter;
    private TlsContext context;
    private TokenBindingExtensionMessage message;
    private TokenBindingExtensionPreparator preparator;

    public TokenBindingExtensionPreparatorTest(ExtensionType extensionType, byte[] extensionBytes, int extensionLength,
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

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new TokenBindingExtensionMessage();
        preparator = new TokenBindingExtensionPreparator(context, (TokenBindingExtensionMessage) message);
    }

    @Test
    public void testPreparator() {
        context.getConfig().setTokenBindingMajor(majorVersion);
        context.getConfig().setTokenBindingMinor(minorVersion);
        ArrayList<TokenBindingKeyParameters> keyParameterArray = new ArrayList<>();
        for (byte kp : keyParameter) {
            keyParameterArray.add(TokenBindingKeyParameters.getExtensionType(kp));
        }
        context.getConfig().setTokenBindingKeyParameters(
                keyParameterArray.toArray(new TokenBindingKeyParameters[keyParameterArray.size()]));

        preparator.prepare();

        assertArrayEquals(ExtensionType.TOKEN_BINDING.getValue(), message.getExtensionType().getValue());
        assertEquals(majorVersion.getByteValue(), (byte) message.getMajorTokenbindingVersion().getValue());
        assertEquals(minorVersion.getByteValue(), (byte) message.getMinorTokenbindingVersion().getValue());
        assertArrayEquals(keyParameter, message.getTokenbindingKeyParameters().getValue());
    }

}
