/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.UnknownMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownMessageParser extends Parser<UnknownMessage> {

    public UnknownMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UnknownMessage parse() {
        UnknownMessage message = new UnknownMessage();
        parseCompleteMessage(message);
        return message;
    }

    /**
     * Since we dont know what this is, we cannot make assumptions about length
     * fields or the such, so we assume that all data we received in the array
     * is part of this unknown message
     */
    private void parseCompleteMessage(UnknownMessage message) {
        message.setCompleteResultingMessage(parseByteArrayField(getBytesLeft()));
    }

}
