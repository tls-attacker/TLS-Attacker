/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptThenMacExtensionMessage;

public class EncryptThenMacExtensionSerializer extends ExtensionSerializer<EncryptThenMacExtensionMessage> {

    public EncryptThenMacExtensionSerializer(EncryptThenMacExtensionMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeExtensionContent() {
        return getAlreadySerialized();
    }

}
