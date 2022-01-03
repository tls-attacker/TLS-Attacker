/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
