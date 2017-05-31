/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TokenBindingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TokenBindingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TokenBindingExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class TokenBindingExtensionHandlerTest extends ExtensionHandlerTest {

    private final ExtensionType extensionType;
    private final byte[] extensionBytes;
    private final int extensionLength;
    private final TokenBindingVersion majorVersion;
    private final TokenBindingVersion minorVersion;
    private final int parameterLength;
    private final TokenBindingKeyParameters[] keyParameter;

    public TokenBindingExtensionHandlerTest(ExtensionType extensionType, byte[] extension, int extensionLength,
            TokenBindingVersion majorVersion, TokenBindingVersion minorVersion, int parameterLength,
            TokenBindingKeyParameters[] keyParameter) {
        this.extensionType = extensionType;
        this.extensionBytes = extension;
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
                new TokenBindingKeyParameters[] { TokenBindingKeyParameters.ECDSAP256 } } });
    }

    @Before
    @Override
    public void setUp() {
        context = new TlsContext();
        handler = new TokenBindingExtensionHandler(context);
    }

    @Test
    @Override
    public void testAdjustTLSContext() {
        TokenBindingExtensionMessage message = new TokenBindingExtensionMessage();
        message.setMajor(majorVersion);
        message.setMinor(minorVersion);
        message.setTokenbindingParameters(keyParameter);
        handler.adjustTLSContext(message);

        assertEquals(majorVersion, context.getTokenBindingMajorVersion());
        assertEquals(minorVersion, context.getTokenBindingMinorVersion());
        assertArrayEquals(keyParameter, context.getTokenBindingKeyParameters());
    }

    @Test
    @Override
    public void testGetParser() {
        assertTrue(handler.getParser(extensionBytes, 0) instanceof TokenBindingExtensionParser);
    }

    @Test
    @Override
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new TokenBindingExtensionMessage()) instanceof TokenBindingExtensionPreparator);
    }

    @Test
    @Override
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new TokenBindingExtensionMessage()) instanceof TokenBindingExtensionSerializer);
    }

}
