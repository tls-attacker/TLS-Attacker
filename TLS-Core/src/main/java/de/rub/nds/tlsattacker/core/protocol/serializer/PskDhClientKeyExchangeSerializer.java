/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskDhClientKeyExchangeSerializer
        extends DHClientKeyExchangeSerializer<PskDhClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PskDhClientKeyExchangeMessage msg;

    /**
     * Constructor for the PSKClientKeyExchangeSerializer
     *
     * @param message Message that should be serialized
     */
    public PskDhClientKeyExchangeSerializer(PskDhClientKeyExchangeMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PSKDHClientKeyExchangeMessage");
        writePSKIdentityLength(msg);
        writePSKIdentity(msg);
        super.serializeDhParams();
        return getAlreadySerialized();
    }

    /**
     * Writes the SerializedPublicKeyLength of the PSKClientKeyExchangeMessage into the final byte[]
     */
    private void writePSKIdentityLength(PskDhClientKeyExchangeMessage msg) {
        appendInt(msg.getIdentityLength().getValue(), HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug(
                "SerializedPSKIdentityLength: {}",
                () -> ArrayConverter.bytesToInt(msg.getIdentity().getValue()));
    }

    /** Writes the SerializedPublicKey of the PSKClientKeyExchangeMessage into the final byte[] */
    private void writePSKIdentity(PskDhClientKeyExchangeMessage msg) {
        appendBytes(msg.getIdentity().getValue());
        LOGGER.debug("SerializedPSKIdentity: {}", msg.getIdentity().getValue());
    }
}
