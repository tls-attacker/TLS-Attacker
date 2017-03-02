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
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangeParser extends ServerKeyExchangeParser<DHEServerKeyExchangeMessage> {

    public DHEServerKeyExchangeParser(int pointer, byte[] array) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE);
    }

    @Override
    protected void parseHandshakeMessageContent(DHEServerKeyExchangeMessage msg) {
        msg.setpLength(parseIntField(HandshakeByteLength.DH_P_LENGTH));
        msg.setP(parseBigIntField(msg.getpLength().getValue()));
        msg.setgLength(parseIntField(HandshakeByteLength.DH_G_LENGTH));
        msg.setG(parseBigIntField(msg.getgLength().getValue()));
        msg.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.DH_PUBLICKEY_LENGTH));
        msg.setSerializedPublicKey(parseByteArrayField(msg.getSerializedPublicKeyLength().getValue()));
    }

    @Override
    protected DHEServerKeyExchangeMessage createHandshakeMessage() {
        return new DHEServerKeyExchangeMessage();
    }
}
