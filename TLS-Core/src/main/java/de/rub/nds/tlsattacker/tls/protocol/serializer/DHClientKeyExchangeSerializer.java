/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHClientKeyExchangeSerializer extends ClientKeyExchangeSerializer<DHClientKeyExchangeMessage> {

    private final DHClientKeyExchangeMessage msg;

    /**
     * Constructor for the DHClientKeyExchangeSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public DHClientKeyExchangeSerializer(DHClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeSerializedPublicKeyLength(msg);
        writeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the SerializedPublicKeyLength of the DHClientKeyExchangeMessage
     * into the final byte[]
     */
    private void writeSerializedPublicKeyLength(DHClientKeyExchangeMessage msg) {
        appendInt(msg.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH);
        LOGGER.debug("SerializedPublicKexLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    /**
     * Writes the SerializedPublicKey of the DHClientKeyExchangeMessage into the
     * final byte[]
     */
    private void writeSerializedPublicKey(DHClientKeyExchangeMessage msg) {
        appendBytes(msg.getSerializedPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getSerializedPublicKey().getValue()));
    }
}
