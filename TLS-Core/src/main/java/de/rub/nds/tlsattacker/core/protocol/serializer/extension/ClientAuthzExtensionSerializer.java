/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;

public class ClientAuthzExtensionSerializer extends ExtensionSerializer<ClientAuthzExtensionMessage> {

    private final ClientAuthzExtensionMessage msg;

    public ClientAuthzExtensionSerializer(ClientAuthzExtensionMessage message) {
        super(message);
        msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(msg.getAuthzFormatListLength().getValue(), ExtensionByteLength.CLIENT_AUTHZ_FORMAT_LIST_LENGTH);
        appendBytes(msg.getAuthzFormatList().getValue());

        return getAlreadySerialized();
    }

}
