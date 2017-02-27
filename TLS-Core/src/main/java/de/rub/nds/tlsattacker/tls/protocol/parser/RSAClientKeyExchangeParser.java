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
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RSAClientKeyExchangeParser extends ClientKeyExchangeParser<RSAClientKeyExchangeMessage>{

    public RSAClientKeyExchangeParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ClientKeyExchangeMessage parse() {
        RSAClientKeyExchangeMessage message = new RSAClientKeyExchangeMessage();
        parseType(message);
        parseLength(message);
        //TODO rename keyexchange message field
        message.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH));
        message.setSerializedPublicKey(parseByteArrayField(message.getSerializedPublicKeyLength().getValue()));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }
    
}
