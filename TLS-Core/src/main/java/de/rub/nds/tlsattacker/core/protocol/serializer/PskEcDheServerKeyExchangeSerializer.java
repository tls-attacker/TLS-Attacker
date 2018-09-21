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
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDheServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskEcDheServerKeyExchangeSerializer extends
        ECDHEServerKeyExchangeSerializer<PskEcDheServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PskEcDheServerKeyExchangeMessage msg;

    /**
     * Constructor for the PSKECDHEServerKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PskEcDheServerKeyExchangeSerializer(PskEcDheServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PSKECDHEServerKeyExchangeMessage");
        writePSKIdentityHintLength(msg);
        writePSKIdentityHint(msg);
        super.serializeEcDheParams();
        return getAlreadySerialized();
    }

    private void writePSKIdentityHintLength(PskEcDheServerKeyExchangeMessage msg) {
        appendInt(msg.getIdentityHintLength().getValue(), HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityLength: " + msg.getIdentityHintLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the PskEcDheServerKeyExchangeMessage
     * into the final byte[]
     */
    private void writePSKIdentityHint(PskEcDheServerKeyExchangeMessage msg) {
        appendBytes(msg.getIdentityHint().getValue());
        LOGGER.debug("SerializedPSKIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentityHint().getValue()));
    }
}
