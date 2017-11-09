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
import de.rub.nds.tlsattacker.core.protocol.message.PskServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.serializer.Serializer.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PskServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<PskServerKeyExchangeMessage> {

    private final PskServerKeyExchangeMessage msg;

    /**
     * Constructor for the PSKServerKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PskServerKeyExchangeSerializer(PskServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PSKServerKeyExchangeMessage");
        writePSKIdentityHintLength(msg);
        writePSKIdentityHint(msg);
        return getAlreadySerialized();
    }

    private void writePSKIdentityHintLength(PskServerKeyExchangeMessage msg) {
        appendInt(msg.getIdentityHint().getValue().length, HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityLength: " + ArrayConverter.bytesToInt(msg.getIdentityHint().getValue()));
    }

    /**
     * Writes the SerializedPublicKey of the PskServerKeyExchangeMessage into
 the final byte[]
     */
    private void writePSKIdentityHint(PskServerKeyExchangeMessage msg) {
        appendBytes(msg.getIdentityHint().getValue());
        LOGGER.debug("SerializedPSKIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentityHint().getValue()));
    }
}
