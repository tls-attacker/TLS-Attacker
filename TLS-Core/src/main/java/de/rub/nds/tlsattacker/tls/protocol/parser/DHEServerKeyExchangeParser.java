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
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangeParser extends ServerKeyExchangeParser<DHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    private final ProtocolVersion version;

    public DHEServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version);
        this.version = version;
    }

    @Override
    protected void parseHandshakeMessageContent(DHEServerKeyExchangeMessage msg) {
        msg.setpLength(parseIntField(HandshakeByteLength.DH_P_LENGTH));
        msg.setP(parseBigIntField(msg.getpLength().getValue()));
        msg.setgLength(parseIntField(HandshakeByteLength.DH_G_LENGTH));
        msg.setG(parseBigIntField(msg.getgLength().getValue()));
        msg.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.DH_PUBLICKEY_LENGTH));
        msg.setSerializedPublicKey(parseByteArrayField(msg.getSerializedPublicKeyLength().getValue()));
        if (version == ProtocolVersion.TLS12 || version == ProtocolVersion.DTLS12) {
            msg.setHashAlgorithm(parseByteField(HandshakeByteLength.HASH));
            msg.setSignatureAlgorithm(parseByteField(HandshakeByteLength.SIGNATURE));
        }
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
    }

    @Override
    protected DHEServerKeyExchangeMessage createHandshakeMessage() {
        return new DHEServerKeyExchangeMessage();
    }
}
