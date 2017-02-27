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
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerKeyExchangeMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHEServerKeyExchangeParser extends ServerKeyExchangeParser<ECDHEServerKeyExchangeMessage> {

    public ECDHEServerKeyExchangeParser(int pointer, byte[] array, HandshakeMessageType expectedType) {
        super(pointer, array, expectedType);
    }

    @Override
    public ECDHEServerKeyExchangeMessage parse() {
        ECDHEServerKeyExchangeMessage message = new ECDHEServerKeyExchangeMessage();
        parseType(message);
        parseLength(message);
        message.setCurveType(parseByteField(HandshakeByteLength.ELLIPTIC_CURVE));
        message.setNamedCurve(parseByteArrayField(NamedCurve.LENGTH));
        message.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.ECDHE_PARAM_LENGTH) & 0xFF);
        message.setSerializedPublicKey(parseByteArrayField(message.getSerializedPublicKeyLength().getValue()));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }

}
