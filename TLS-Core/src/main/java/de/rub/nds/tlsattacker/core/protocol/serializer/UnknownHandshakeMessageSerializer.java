/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;

/**
 *

 */
public class UnknownHandshakeMessageSerializer extends HandshakeMessageSerializer<UnknownHandshakeMessage> {

    private final UnknownHandshakeMessage msg;

    /**
     * Constructor for the UnknownHandshakeMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public UnknownHandshakeMessageSerializer(UnknownHandshakeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing UnknownHandshakeMessage");
        writeData(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the Data of the UnknownHandshakeMessage into the final byte[]
     */
    private void writeData(UnknownHandshakeMessage msg) {
        appendBytes(msg.getData().getValue());
        LOGGER.debug("Data: " + ArrayConverter.bytesToHexString(msg.getData().getValue()));
    }

}
