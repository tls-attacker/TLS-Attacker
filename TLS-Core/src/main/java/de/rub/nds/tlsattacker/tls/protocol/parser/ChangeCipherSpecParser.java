/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.ChangeCipherSpecByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.ChangeCipherSpecMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeCipherSpecParser extends Parser<ChangeCipherSpecMessage> {

    public ChangeCipherSpecParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChangeCipherSpecMessage parse() {
        ChangeCipherSpecMessage message = new ChangeCipherSpecMessage();
        message.setCcsProtocolType(parseByteField(ChangeCipherSpecByteLength.TYPE_LENGTH));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }

}
