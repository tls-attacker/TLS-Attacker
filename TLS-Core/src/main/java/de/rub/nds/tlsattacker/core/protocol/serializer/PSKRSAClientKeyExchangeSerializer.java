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
import de.rub.nds.tlsattacker.core.protocol.message.PSKRSAClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.serializer.Serializer.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKRSAClientKeyExchangeSerializer extends HandshakeMessageSerializer<PSKRSAClientKeyExchangeMessage> {
    private final PSKRSAClientKeyExchangeMessage msg;

    /**
     * Constructor for the PSKRSAClientKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public PSKRSAClientKeyExchangeSerializer(PSKRSAClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing PSKRSAClientKeyExchangeMessage");
        writePSKIdentityLength(msg);
        writePSKIdentity(msg);
        writeEncryptedPreMasterSecretLength(msg);
        writeEncryptedPreMasterSecret(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the SerializedPublicKeyLength of the
     * PSKRSAClientKeyExchangeMessage into the final byte[]
     */
    private void writePSKIdentityLength(PSKRSAClientKeyExchangeMessage msg) {
        appendInt(msg.getIdentity().getValue().length, HandshakeByteLength.PSK_IDENTITY_LENGTH);
        LOGGER.debug("SerializedPSKIdentityLength: " + ArrayConverter.bytesToInt(msg.getIdentity().getValue()));
    }

    /**
     * Writes the SerializedPublicKey of the PSKRSAClientKeyExchangeMessage into
     * the final byte[]
     */
    private void writePSKIdentity(PSKRSAClientKeyExchangeMessage msg) {
        appendBytes(msg.getIdentity().getValue());
        LOGGER.debug("SerializedPSKIdentity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }

    private void writeEncryptedPreMasterSecret(PSKRSAClientKeyExchangeMessage msg) {
        appendBytes(msg.getComputations().getEncryptedPremasterSecret().getValue());
        LOGGER.debug("SerializedEncryptedPreMasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getEncryptedPremasterSecret().getValue()));
    }

    private void writeEncryptedPreMasterSecretLength(PSKRSAClientKeyExchangeMessage msg) {
        appendBytes(msg.getComputations().getEncryptedPremasterSecretLength().getValue());
    }
}
