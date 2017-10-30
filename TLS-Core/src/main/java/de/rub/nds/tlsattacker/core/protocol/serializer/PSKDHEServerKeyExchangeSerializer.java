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
import de.rub.nds.tlsattacker.core.protocol.message.PSKDHEServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.serializer.Serializer.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKDHEServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<PSKDHEServerKeyExchangeMessage> {

    private final PSKDHEServerKeyExchangeMessage msg;

    /**
     * Constructor for the PSKDHServerKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PSKDHEServerKeyExchangeSerializer(PSKDHEServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PSKDHEServerKeyExchangeMessage");
        writePSKIdentityHintLength(msg);
        writePSKIdentityHint(msg);
        writePLength(msg);
        writeP(msg);
        writeGLength(msg);
        writeG(msg);
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the pLength of the PSKDHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writePLength(PSKDHEServerKeyExchangeMessage msg) {
        appendInt(msg.getModulusLength().getValue(), HandshakeByteLength.DH_MODULUS_LENGTH);
        LOGGER.debug("pLength: " + msg.getModulusLength().getValue());
    }

    /**
     * Writes the P of the PSKDHEServerKeyExchangeMessage into the final byte[]
     */
    private void writeP(PSKDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getModulus().getValue());
        LOGGER.debug("P: " + ArrayConverter.bytesToHexString(msg.getModulus().getValue()));
    }

    /**
     * Writes the gLength of the PSKDHEServerKeyExchangeMessage into the final
     * byte[]
     */
    private void writeGLength(PSKDHEServerKeyExchangeMessage msg) {
        appendInt(msg.getGeneratorLength().getValue(), HandshakeByteLength.DH_GENERATOR_LENGTH);
        LOGGER.debug("gLength: " + msg.getGeneratorLength().getValue());
    }

    /**
     * Writes the G of the PSKDHEServerKeyExchangeMessage into the final byte[]
     */
    private void writeG(PSKDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getGenerator().getValue());
        LOGGER.debug("G: " + ArrayConverter.bytesToHexString(msg.getGenerator().getValue()));
    }

    /**
     * Writes the SerializedPublicKeyLength of the
     * PSKDHEServerKeyExchangeMessage into the final byte[]
     */
    private void writeSerializedPublicKeyLength(PSKDHEServerKeyExchangeMessage msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the PSKDHEServerKeyExchangeMessage into
     * the final byte[]
     */
    private void writeSerializedPublicKey(PSKDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    private void writePSKIdentityHintLength(PSKDHEServerKeyExchangeMessage msg) {
        appendInt(msg.getIdentityHint().getValue().length, HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityLength: " + ArrayConverter.bytesToInt(msg.getIdentityHint().getValue()));
    }

    /**
     * Writes the SerializedPublicKey of the PSKDHEServerKeyExchangeMessage into
     * the final byte[]
     */
    private void writePSKIdentityHint(PSKDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getIdentityHint().getValue());
        LOGGER.debug("SerializedPSKIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentityHint().getValue()));
    }
}
