/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TokenBindingExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.TokenBindingExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.TokenBindingExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class TokenBindingExtensionHandlerTest {

    private final byte[] extensionBytes = new byte[] { 0x00, 0x18, 0x00, 0x04, 0x00, 0x0d, 0x01, 0x02 };

    private final TokenBindingVersion tokenbindingVersion = TokenBindingVersion.DRAFT_13;

    private final TokenBindingKeyParameters[] keyParameter = new TokenBindingKeyParameters[] {
            TokenBindingKeyParameters.RSA2048_PSS, TokenBindingKeyParameters.ECDSAP256 };
    private final byte[] keyParameterByteArrayRepresentation = new byte[] { 0x01, 0x02 };
    private TlsContext context;
    private TokenBindingExtensionHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new TokenBindingExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        TokenBindingExtensionMessage message = new TokenBindingExtensionMessage();
        message.setTokenbindingVersion(tokenbindingVersion.getByteValue());
        message.setTokenbindingKeyParameters(keyParameterByteArrayRepresentation);
        handler.adjustTLSContext(message);

        assertEquals(tokenbindingVersion, context.getTokenBindingVersion());
        assertArrayEquals(
                keyParameter,
                context.getTokenBindingKeyParameters().toArray(
                        new TokenBindingKeyParameters[context.getTokenBindingKeyParameters().size()]));
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(extensionBytes, 0) instanceof TokenBindingExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new TokenBindingExtensionMessage()) instanceof TokenBindingExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new TokenBindingExtensionMessage()) instanceof TokenBindingExtensionSerializer);
    }

}
