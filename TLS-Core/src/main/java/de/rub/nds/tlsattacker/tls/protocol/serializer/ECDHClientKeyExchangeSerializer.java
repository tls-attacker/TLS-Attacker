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
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHClientKeyExchangeSerializer extends ClientKeyExchangeSerializer<ECDHClientKeyExchangeMessage> {

    private final ECDHClientKeyExchangeMessage message;

    public ECDHClientKeyExchangeSerializer(ECDHClientKeyExchangeMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        appendInt(message.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.ECDH_PARAM_LENGTH);
        appendBytes(message.getSerializedPublicKey().getValue());
        return getAlreadySerialized();
    }

}
