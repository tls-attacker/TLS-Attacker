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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PSKClientKeyExchangeMessage;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKClientKeyExchangeSerializer extends HandshakeMessageSerializer<PSKClientKeyExchangeMessage> {
    private final PSKClientKeyExchangeMessage msg;

    /**
     * Constructor for the PSKClientKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PSKClientKeyExchangeSerializer(PSKClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PSKClientKeyExchangeMessage");
        writePskIdentityLength(msg);
        writePskIdentity(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the PskIdentityLength of the PSKClientKeyExchangeMessage into the
     * final byte[]
     */
    private void writePskIdentityLength(PSKClientKeyExchangeMessage msg) {
        appendInt(msg.getIdentity().getValue().length, HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("PskIdentityLength: " + ArrayConverter.bytesToInt(msg.getIdentity().getValue()));
    }

    /**
     * Writes the pskIdentity of the PSKClientKeyExchangeMessage into the final
     * byte[]
     */
    private void writePskIdentity(PSKClientKeyExchangeMessage msg) {
        appendBytes(msg.getIdentity().getValue());
        LOGGER.debug("PskIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }
}
