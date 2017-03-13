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
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ChangeCipherSpecMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeCipherSpecParser extends ProtocolMessageParser<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    public ChangeCipherSpecParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected ChangeCipherSpecMessage parseMessageContent() {
        ChangeCipherSpecMessage msg = new ChangeCipherSpecMessage();
        msg.setCcsProtocolType(parseByteField(ChangeCipherSpecByteLength.TYPE_LENGTH));
        return msg;
    }

}
