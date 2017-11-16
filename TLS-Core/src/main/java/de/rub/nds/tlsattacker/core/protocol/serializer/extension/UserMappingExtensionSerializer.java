/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.UserMappingExtensionMessage;

public class UserMappingExtensionSerializer extends ExtensionSerializer<UserMappingExtensionMessage> {

    private final UserMappingExtensionMessage msg;

    public UserMappingExtensionSerializer(UserMappingExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendByte(msg.getUserMappingType().getValue());

        return getAlreadySerialized();
    }

}
