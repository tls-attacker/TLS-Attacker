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
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<DHEServerKeyExchangeMessage> {

    private DHEServerKeyExchangeMessage message;

    public DHEServerKeyExchangeSerializer(DHEServerKeyExchangeMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        appendInt(message.getpLength().getValue(), HandshakeByteLength.DH_P_LENGTH);
        appendBytes(message.getP().getByteArray());
        appendInt(message.getgLength().getValue(), HandshakeByteLength.DH_G_LENGTH);
        appendBytes(message.getG().getByteArray());
        appendInt(message.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH);
        appendBytes(message.getSerializedPublicKey().getValue());
        return getAlreadySerialized();
    }

}
