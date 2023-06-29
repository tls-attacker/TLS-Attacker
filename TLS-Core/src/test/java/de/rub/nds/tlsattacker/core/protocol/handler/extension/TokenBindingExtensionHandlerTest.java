/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import org.junit.jupiter.api.Test;

public class TokenBindingExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                TokenBindingExtensionMessage, TokenBindingExtensionHandler> {

    private final byte[] extensionBytes =
            new byte[] {0x00, 0x18, 0x00, 0x04, 0x00, 0x0d, 0x01, 0x02};

    private final TokenBindingVersion tokenBindingVersion = TokenBindingVersion.DRAFT_13;

    private final TokenBindingKeyParameters[] keyParameter =
            new TokenBindingKeyParameters[] {
                TokenBindingKeyParameters.RSA2048_PSS, TokenBindingKeyParameters.ECDSAP256
            };
    private final byte[] keyParameterByteArrayRepresentation = new byte[] {0x01, 0x02};

    public TokenBindingExtensionHandlerTest() {
        super(TokenBindingExtensionMessage::new, TokenBindingExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        TokenBindingExtensionMessage message = new TokenBindingExtensionMessage();
        message.setTokenBindingVersion(tokenBindingVersion.getByteValue());
        message.setTokenBindingKeyParameters(keyParameterByteArrayRepresentation);
        handler.adjustTLSExtensionContext(message);

        assertEquals(tokenBindingVersion, context.getTokenBindingVersion());
        assertArrayEquals(
                keyParameter,
                context.getTokenBindingKeyParameters().toArray(new TokenBindingKeyParameters[0]));
    }
}
