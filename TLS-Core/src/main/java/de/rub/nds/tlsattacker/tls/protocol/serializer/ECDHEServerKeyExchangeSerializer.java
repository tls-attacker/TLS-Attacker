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
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHEServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<ECDHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");
    
    private final ECDHEServerKeyExchangeMessage message;

    public ECDHEServerKeyExchangeSerializer(ECDHEServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        appendByte(message.getCurveType().getValue());
        appendBytes(message.getNamedCurve().getValue());
        appendInt(message.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.ECDHE_PARAM_LENGTH);
        appendBytes(message.getSerializedPublicKey().getValue());
        if (version == ProtocolVersion.TLS12 || version == ProtocolVersion.DTLS12) {
            appendByte(message.getHashAlgorithm().getValue());
            appendByte(message.getSignatureAlgorithm().getValue());
        }
        appendInt(message.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        appendBytes(message.getSignature().getValue());
        return getAlreadySerialized();
    }

}
