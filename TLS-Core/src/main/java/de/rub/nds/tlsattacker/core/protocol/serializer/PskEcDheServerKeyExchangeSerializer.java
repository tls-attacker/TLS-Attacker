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
import static de.rub.nds.tlsattacker.core.protocol.serializer.Serializer.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PskEcDheServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<PskEcDheServerKeyExchangeMessage> {

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
        writeCurveType(msg);
        writeNamedCurve(msg);
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    private void writePSKIdentityHintLength(PskEcDheServerKeyExchangeMessage msg) {
        appendInt(msg.getIdentityHint().getValue().length, HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityLength: " + ArrayConverter.bytesToInt(msg.getIdentityHint().getValue()));
    }

    /**
     * Writes the SerializedPublicKey of the PskEcDheServerKeyExchangeMessage
 into the final byte[]
     */
    private void writePSKIdentityHint(PskEcDheServerKeyExchangeMessage msg) {
        appendBytes(msg.getIdentityHint().getValue());
        LOGGER.debug("SerializedPSKIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentityHint().getValue()));
    }

    /**
     * Writes the CurveType of the PskEcDheServerKeyExchangeMessage into the
 final byte[]
     */
    private void writeCurveType(PskEcDheServerKeyExchangeMessage msg) {
        appendByte(msg.getCurveType().getValue());
        LOGGER.debug("CurveType: " + msg.getCurveType().getValue());
    }

    /**
     * Writes the NamedCurve of the PskEcDheServerKeyExchangeMessage into the
 final byte[]
     */
    private void writeNamedCurve(PskEcDheServerKeyExchangeMessage msg) {
        appendBytes(msg.getNamedCurve().getValue());
        LOGGER.debug("NamedCurve: " + ArrayConverter.bytesToHexString(msg.getNamedCurve().getValue()));
    }

    /**
     * Writes the SerializedPublicKeyLength of the
 PskEcDheServerKeyExchangeMessage into the final byte[]
     */
    private void writeSerializedPublicKeyLength(PskEcDheServerKeyExchangeMessage msg) {
        appendInt(msg.getPublicKeyLength().getValue(), HandshakeByteLength.ECDHE_PARAM_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the PskEcDheServerKeyExchangeMessage
 into the final byte[]
     */
    private void writeSerializedPublicKey(PskEcDheServerKeyExchangeMessage msg) {
        appendBytes(msg.getPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }
}
