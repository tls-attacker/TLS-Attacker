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
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHClientKeyExchangeParser extends ClientKeyExchangeParser<ECDHClientKeyExchangeMessage>{

    public ECDHClientKeyExchangeParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ECDHClientKeyExchangeMessage parse() {
        ECDHClientKeyExchangeMessage message = new ECDHClientKeyExchangeMessage();
        parseType(message);
        parseLength(message);
        message.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.ECDH_PARAM_LENGTH));
        message.setSerializedPublicKey(parseByteArrayField(message.getSerializedPublicKeyLength().getValue()));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }
    
}
