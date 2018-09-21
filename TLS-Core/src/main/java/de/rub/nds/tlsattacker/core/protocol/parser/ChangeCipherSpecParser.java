/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ChangeCipherSpecByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeCipherSpecParser extends ProtocolMessageParser<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *            Position in the array where the ProtocolMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ProtocolMessageParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public ChangeCipherSpecParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected ChangeCipherSpecMessage parseMessageContent() {
        LOGGER.debug("Parsing ChangeCipherSpecMessage");
        ChangeCipherSpecMessage msg = new ChangeCipherSpecMessage();
        parseCcsProtocolType(msg);
        return msg;
    }

    /**
     * Reads the next bytes as the CcsProtocolType and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCcsProtocolType(ChangeCipherSpecMessage msg) {
        msg.setCcsProtocolType(parseByteField(ChangeCipherSpecByteLength.TYPE_LENGTH));
        LOGGER.debug("CcsProtocolType: " + msg.getCcsProtocolType().getValue());
    }

}
