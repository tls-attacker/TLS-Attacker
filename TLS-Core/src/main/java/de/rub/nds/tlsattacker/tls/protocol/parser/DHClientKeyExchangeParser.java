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
import de.rub.nds.tlsattacker.tls.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.DHClientKeyExchangeMessage;
import java.math.BigInteger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHClientKeyExchangeParser extends ClientKeyExchangeParser<DHClientKeyExchangeMessage> {

    public DHClientKeyExchangeParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    protected void parseHandshakeMessageContent(DHClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.DH_P_LENGTH));
        msg.setSerializedPublicKey(parseByteArrayField(msg.getSerializedPublicKeyLength().getValue()));
    }

    @Override
    protected DHClientKeyExchangeMessage createHandshakeMessage() {
        return new DHClientKeyExchangeMessage();
    }
}
