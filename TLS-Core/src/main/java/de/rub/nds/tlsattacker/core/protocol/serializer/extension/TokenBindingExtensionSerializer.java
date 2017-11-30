/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;

public class TokenBindingExtensionSerializer extends ExtensionSerializer<TokenBindingExtensionMessage> {

    private final TokenBindingExtensionMessage message;

    public TokenBindingExtensionSerializer(TokenBindingExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(message.getTokenbindingVersion().getValue());
        appendInt(message.getParameterListLength().getValue(), 1);
        appendBytes(message.getTokenbindingKeyParameters().getValue());

        return getAlreadySerialized();
    }
}
