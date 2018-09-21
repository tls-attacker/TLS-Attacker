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
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskEcDhClientKeyExchangeSerializer extends
        ECDHClientKeyExchangeSerializer<PskEcDhClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PskEcDhClientKeyExchangeMessage msg;

    /**
     * Constructor for the PSKECDHClientKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PskEcDhClientKeyExchangeSerializer(PskEcDhClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PSKECDHClientKeyExchangeMessage");
        writePSKIdentityLength(msg);
        writePSKIdentity(msg);
        super.serializeEcDhParams();
        return getAlreadySerialized();
    }

    /**
     * Writes the SerializedPublicKeyLength of the
     * PskEcDhClientKeyExchangeMessage into the final byte[]
     */
    private void writePSKIdentityLength(PskEcDhClientKeyExchangeMessage msg) {
        appendInt(msg.getIdentityLength().getValue(), HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityLength: " + ArrayConverter.bytesToInt(msg.getIdentity().getValue()));
    }

    /**
     * Writes the SerializedPublicKey of the PskEcDhClientKeyExchangeMessage
     * into the final byte[]
     */
    private void writePSKIdentity(PskEcDhClientKeyExchangeMessage msg) {
        appendBytes(msg.getIdentity().getValue());
        LOGGER.debug("SerializedPSKIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }
}
