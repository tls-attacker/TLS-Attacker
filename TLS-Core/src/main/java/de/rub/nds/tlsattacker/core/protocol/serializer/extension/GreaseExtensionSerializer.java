/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.GreaseExtensionMessage;

public class GreaseExtensionSerializer extends ExtensionSerializer<GreaseExtensionMessage> {

    private final GreaseExtensionMessage msg;

    public GreaseExtensionSerializer(GreaseExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(msg.getRandomData().getValue());
        return getAlreadySerialized();
    }
}
