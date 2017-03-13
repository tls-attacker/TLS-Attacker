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
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHClientKeyExchangeSerializer extends ClientKeyExchangeSerializer<ECDHClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private final ECDHClientKeyExchangeMessage message;

    public ECDHClientKeyExchangeSerializer(ECDHClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        appendInt(message.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.ECDH_PARAM_LENGTH);
        appendBytes(message.getSerializedPublicKey().getValue());
        return getAlreadySerialized();
    }

}
