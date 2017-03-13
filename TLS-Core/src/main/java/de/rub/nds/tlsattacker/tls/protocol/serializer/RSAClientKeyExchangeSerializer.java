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
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RSAClientKeyExchangeSerializer extends HandshakeMessageSerializer<RSAClientKeyExchangeMessage> {

    private final RSAClientKeyExchangeMessage message;

    public RSAClientKeyExchangeSerializer(RSAClientKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        appendInt(message.getSerializedPublicKeyLength().getValue(),
                HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH);
        appendBytes(message.getSerializedPublicKey().getValue());
        return getAlreadySerialized();
    }
}
