/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;

public class PaddingExtensionSerializer extends ExtensionSerializer<PaddingExtensionMessage> {

    private final PaddingExtensionMessage message;

    public PaddingExtensionSerializer(PaddingExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(message.getPaddingBytes().getValue());
        LOGGER.debug("Serialized PaddingExtension with " + message.getPaddingBytes().getValue().length
                + " padding bytes.");
        return getAlreadySerialized();
    }

}
