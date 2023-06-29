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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNameIndicationExtensionSerializer
        extends ExtensionSerializer<ServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerNameIndicationExtensionMessage msg;

    public ServerNameIndicationExtensionSerializer(ServerNameIndicationExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing ServerNameIndicationExtensionMessage");
        writeServerNameListLength(msg);
        writeServerNameListBytes(msg);
        return getAlreadySerialized();
    }

    private void writeServerNameListLength(ServerNameIndicationExtensionMessage msg) {
        appendInt(msg.getServerNameListLength().getValue(), ExtensionByteLength.SERVER_NAME_LIST);
        LOGGER.debug("ServerNameListLength: " + msg.getServerNameListLength().getValue());
    }

    private void writeServerNameListBytes(ServerNameIndicationExtensionMessage msg) {
        appendBytes(msg.getServerNameListBytes().getValue());
        LOGGER.debug("ServerNameListBytes: {}", msg.getServerNameListBytes().getValue());
    }
}
