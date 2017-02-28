/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class FinishedMessageParser extends HandshakeMessageParser<FinishedMessage> {

    public FinishedMessageParser(int pointer, byte[] array) {
        super(pointer, array, HandshakeMessageType.FINISHED);
    }

    @Override
    public FinishedMessage parse() {
        FinishedMessage message = new FinishedMessage();
        parseType(message);
        parseLength(message);
        message.setVerifyData(parseByteArrayField(message.getLength().getValue()));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }

}
