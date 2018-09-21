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
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskDheServerKeyExchangeSerializer extends DHEServerKeyExchangeSerializer<PskDheServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PskDheServerKeyExchangeMessage msg;

    /**
     * Constructor for the PSKDHServerKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PskDheServerKeyExchangeSerializer(PskDheServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PSKDHEServerKeyExchangeMessage");
        writePSKIdentityHintLength(msg);
        writePSKIdentityHint(msg);
        super.serializeDheParams();
        return getAlreadySerialized();
    }

    private void writePSKIdentityHintLength(PskDheServerKeyExchangeMessage msg) {
        appendInt(msg.getIdentityHintLength().getValue(), HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityHintLength: " + msg.getIdentityHintLength());
    }

    /**
     * Writes the SerializedPublicKey of the PskDheServerKeyExchangeMessage into
     * the final byte[]
     */
    private void writePSKIdentityHint(PskDheServerKeyExchangeMessage msg) {
        appendBytes(msg.getIdentityHint().getValue());
        LOGGER.debug("SerializedPSKIdentityHint: " + ArrayConverter.bytesToHexString(msg.getIdentityHint().getValue()));
    }
}
