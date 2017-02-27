/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.AlertByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AlertParser extends Parser<AlertMessage> {

    public AlertParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public AlertMessage parse() {
        AlertMessage message = new AlertMessage();
        message.setLevel(parseByteField(AlertByteLength.LEVEL_LENGTH));
        message.setDescription(parseByteField(AlertByteLength.DESCRIPTION_LENGTH));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }
}
