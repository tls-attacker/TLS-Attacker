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
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHClientKeyExchangeSerializer extends ClientKeyExchangeSerializer<ECDHClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private final ECDHClientKeyExchangeMessage msg;

    public ECDHClientKeyExchangeSerializer(ECDHClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        serializeSerializedPublicKeyLength(msg);
        serializeSerializedPublicKey(msg);
        return getAlreadySerialized();
    }

    private void serializeSerializedPublicKeyLength(ECDHClientKeyExchangeMessage msg) {
        appendInt(msg.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.ECDH_PARAM_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: "+ msg.getSerializedPublicKeyLength().getValue());
    }

    private void serializeSerializedPublicKey(ECDHClientKeyExchangeMessage msg) {
        appendBytes(msg.getSerializedPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: "+ Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }

}
