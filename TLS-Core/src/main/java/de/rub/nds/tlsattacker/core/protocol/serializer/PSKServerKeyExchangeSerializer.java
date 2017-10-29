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
import de.rub.nds.tlsattacker.core.protocol.message.PSKServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.serializer.Serializer.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<PSKServerKeyExchangeMessage> {

    private final PSKServerKeyExchangeMessage msg;

    /**
     * Constructor for the PSKDHServerKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PSKServerKeyExchangeSerializer(PSKServerKeyExchangeMessage message, ProtocolVersion version) {
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

    private void writePSKIdentityHintLength(PSKServerKeyExchangeMessage msg) {
        appendInt(msg.getIdentityHint().getValue().length, HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityLength: " + ArrayConverter.bytesToInt(msg.getIdentityHint().getValue()));
    }

    /**
     * Writes the SerializedPublicKey of the PSKClientKeyExchangeMessage into
     * the final byte[]
     */
    private void writePSKIdentityHint(PSKServerKeyExchangeMessage msg) {
        appendBytes(msg.getIdentityHint().getValue());
        LOGGER.debug("SerializedPSKIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentityHint().getValue()));
    }
}
