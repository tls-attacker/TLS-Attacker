/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.NewConnectionIdMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewConnectionIdSerializer extends HandshakeMessageSerializer<NewConnectionIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final NewConnectionIdMessage msg;

    public NewConnectionIdSerializer(NewConnectionIdMessage message) {
        super(message);

        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing NewConnectionId");
        serializeCidsLength(msg);
        serializeCids(msg);
        serializeUsage(msg);
        return getAlreadySerialized();
    }

    private void serializeUsage(NewConnectionIdMessage msg) {
        appendByte(msg.getUsage().getValue());
        LOGGER.debug("Usage: " + msg.getUsage().getValue());
    }

    private void serializeCids(NewConnectionIdMessage msg) {
        appendBytes(msg.getConnectionIds().getValue());
        LOGGER.debug("ConnectionIds: " + ArrayConverter.bytesToHexString(msg.getConnectionIds()));
    }

    private void serializeCidsLength(NewConnectionIdMessage msg) {
        appendInt(
                msg.getConnectionIdsLength().getValue(),
                HandshakeByteLength.NEWCONNECTIONID_CIDS_LENGTH);
        LOGGER.debug("ConnectionIdsLength: " + msg.getConnectionIdsLength());
    }
}
