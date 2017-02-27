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

    public DHEServerKeyExchangeParser(int pointer, byte[] array, HandshakeMessageType expectedType) {
        super(pointer, array, expectedType);
    }

    @Override
    public DHEServerKeyExchangeMessage parse() {
        DHEServerKeyExchangeMessage message = new DHEServerKeyExchangeMessage();
        parseType(message);
        parseLength(message);
        message.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.DHE_PARAM_LENGTH));
        message.setSerializedPublicKey(parseByteArrayField(message.getSerializedPublicKeyLength().getValue()));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }
}
