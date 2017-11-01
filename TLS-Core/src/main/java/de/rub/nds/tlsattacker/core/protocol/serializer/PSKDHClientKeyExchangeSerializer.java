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
import de.rub.nds.tlsattacker.core.protocol.message.PSKDHClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.serializer.Serializer.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKDHClientKeyExchangeSerializer extends HandshakeMessageSerializer<PSKDHClientKeyExchangeMessage> {
    private final PSKDHClientKeyExchangeMessage msg;

    /**
     * Constructor for the PSKClientKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PSKDHClientKeyExchangeSerializer(PSKDHClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PSKDHClientKeyExchangeMessage");
        writePSKIdentityLength(msg);
        writePSKIdentity(msg);
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the SerializedPublicKeyLength of the PSKClientKeyExchangeMessage
     * into the final byte[]
     */
    private void writePSKIdentityLength(PSKDHClientKeyExchangeMessage msg) {
        appendInt(msg.getIdentity().getValue().length, HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityLength: " + ArrayConverter.bytesToInt(msg.getIdentity().getValue()));
    }

    /**
     * Writes the SerializedPublicKey of the PSKClientKeyExchangeMessage into
     * the final byte[]
     */
    private void writePSKIdentity(PSKDHClientKeyExchangeMessage msg) {
        appendBytes(msg.getIdentity().getValue());
        LOGGER.debug("SerializedPSKIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }

    /**
     * Writes the SerializedPublicKeyLength of the PSKClientKeyExchangeMessage
     * into the final byte[]
     */
    private void writeSerializedPublicKeyLength(PSKDHClientKeyExchangeMessage msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH);
        LOGGER.debug("SerializedPublicKexLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the PSKClientKeyExchangeMessage into
     * the final byte[]
     */
    private void writeSerializedPublicKey(PSKDHClientKeyExchangeMessage msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }
}
