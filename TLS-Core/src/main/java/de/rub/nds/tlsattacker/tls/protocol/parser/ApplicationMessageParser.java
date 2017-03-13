/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ApplicationMessageParser extends ProtocolMessageParser<ApplicationMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    public ApplicationMessageParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected ApplicationMessage parseMessageContent() {
        ApplicationMessage message = new ApplicationMessage();
        message.setData(parseByteArrayField(getBytesLeft()));
        return message;
    }

}
