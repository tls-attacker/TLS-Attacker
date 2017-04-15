/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ServerNameIndicationExtensionMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerNameIndicationExtensionSerializer extends ExtensionSerializer<ServerNameIndicationExtensionMessage> {

    private final ServerNameIndicationExtensionMessage message;

    public ServerNameIndicationExtensionSerializer(ServerNameIndicationExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(message.getServerNameListLength().getValue(), ExtensionByteLength.SERVER_NAME_LIST_LENGTH);
        appendBytes(message.getServerNameListBytes().getValue());
        return getAlreadySerialized();
    }
}
