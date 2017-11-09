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
import static de.rub.nds.tlsattacker.core.protocol.serializer.Serializer.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PskDheServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<PskDheServerKeyExchangeMessage> {

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
        writePLength(msg);
        writeP(msg);
        writeGLength(msg);
        writeG(msg);
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the pLength of the PskDheServerKeyExchangeMessage into the final
 byte[]
     */
    private void writePLength(PskDheServerKeyExchangeMessage msg) {
        appendInt(msg.getModulusLength().getValue(), HandshakeByteLength.DH_MODULUS_LENGTH);
        LOGGER.debug("pLength: " + msg.getModulusLength().getValue());
    }

    /**
     * Writes the P of the PskDheServerKeyExchangeMessage into the final byte[]
     */
    private void writeP(PskDheServerKeyExchangeMessage msg) {
        appendBytes(msg.getModulus().getValue());
        LOGGER.debug("P: " + ArrayConverter.bytesToHexString(msg.getModulus().getValue()));
    }

    /**
     * Writes the gLength of the PskDheServerKeyExchangeMessage into the final
 byte[]
     */
    private void writeGLength(PskDheServerKeyExchangeMessage msg) {
        appendInt(msg.getGeneratorLength().getValue(), HandshakeByteLength.DH_GENERATOR_LENGTH);
        LOGGER.debug("gLength: " + msg.getGeneratorLength().getValue());
    }

    /**
     * Writes the G of the PskDheServerKeyExchangeMessage into the final byte[]
     */
    private void writeG(PskDheServerKeyExchangeMessage msg) {
        appendBytes(msg.getGenerator().getValue());
        LOGGER.debug("G: " + ArrayConverter.bytesToHexString(msg.getGenerator().getValue()));
    }

    /**
     * Writes the SerializedPublicKeyLength of the
 PskDheServerKeyExchangeMessage into the final byte[]
     */
    private void writeSerializedPublicKeyLength(PskDheServerKeyExchangeMessage msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the PskDheServerKeyExchangeMessage into
 the final byte[]
     */
    private void writeSerializedPublicKey(PskDheServerKeyExchangeMessage msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    private void writePSKIdentityHintLength(PskDheServerKeyExchangeMessage msg) {
        appendInt(msg.getIdentityHintLength().getValue(), HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityLength: " + ArrayConverter.bytesToInt(msg.getIdentityHint().getValue()));
    }

    /**
     * Writes the SerializedPublicKey of the PskDheServerKeyExchangeMessage into
 the final byte[]
     */
    private void writePSKIdentityHint(PskDheServerKeyExchangeMessage msg) {
        appendBytes(msg.getIdentityHint().getValue());
        LOGGER.debug("SerializedPSKIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentityHint().getValue()));
    }
}
