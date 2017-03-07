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
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHEServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<ECDHEServerKeyExchangeMessage> {

    private final ECDHEServerKeyExchangeMessage message;

    public ECDHEServerKeyExchangeSerializer(ECDHEServerKeyExchangeMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        appendByte(message.getCurveType().getValue());
        appendBytes(message.getNamedCurve().getValue());
        appendInt(message.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.ECDHE_PARAM_LENGTH);
        appendBytes(message.getSerializedPublicKey().getValue());
        appendByte(message.getHashAlgorithm().getValue());
        appendByte(message.getSignatureAlgorithm().getValue());
        appendInt(message.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        appendBytes(message.getSignature().getValue());
        return getAlreadySerialized();
    }

}
