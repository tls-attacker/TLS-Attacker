/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerAuthzExtensionMessage;

public class ServerAuthzExtensionSerializer
        extends ExtensionSerializer<ServerAuthzExtensionMessage> {

    private final ServerAuthzExtensionMessage msg;

    public ServerAuthzExtensionSerializer(ServerAuthzExtensionMessage message) {
        super(message);
        msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(
                msg.getAuthzFormatListLength().getValue(),
                ExtensionByteLength.SERVER_AUTHZ_FORMAT_LIST_LENGTH);
        appendBytes(msg.getAuthzFormatList().getValue());

        return getAlreadySerialized();
    }
}
