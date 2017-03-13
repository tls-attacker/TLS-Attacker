/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHEServerKeyExchangeParser extends ServerKeyExchangeParser<ECDHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    private final ProtocolVersion version;

    public ECDHEServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version);
        this.version = version;
    }

    @Override
    protected void parseHandshakeMessageContent(ECDHEServerKeyExchangeMessage msg) {
        msg.setCurveType(parseByteField(HandshakeByteLength.ELLIPTIC_CURVE));
        msg.setNamedCurve(parseByteArrayField(NamedCurve.LENGTH));
        msg.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.ECDHE_PARAM_LENGTH));
        msg.setSerializedPublicKey(parseByteArrayField(msg.getSerializedPublicKeyLength().getValue()));
        if (version == ProtocolVersion.TLS12 || version == ProtocolVersion.DTLS12) {
            msg.setHashAlgorithm(parseByteField(HandshakeByteLength.HASH));
            msg.setSignatureAlgorithm(parseByteField(HandshakeByteLength.SIGNATURE));
        }
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
    }

    @Override
    protected ECDHEServerKeyExchangeMessage createHandshakeMessage() {
        return new ECDHEServerKeyExchangeMessage();
    }

}
