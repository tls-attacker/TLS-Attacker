/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension.quic;

import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.QuicTransportParametersExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;

public class QuicTransportParametersExtensionsSerializer
        extends ExtensionSerializer<QuicTransportParametersExtensionMessage> {

    private final QuicTransportParametersExtensionMessage message;

    public QuicTransportParametersExtensionsSerializer(
            QuicTransportParametersExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(message.getParameterExtensions().getValue());
        return getAlreadySerialized();
    }
}
