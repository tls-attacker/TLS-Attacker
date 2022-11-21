/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChangeCipherSpecByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeCipherSpecParser extends TlsMessageParser<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *                      Position in the array where the ProtocolMessageParser is supposed to start parsing
     * @param array
     *                      The byte[] which the ProtocolMessageParser is supposed to parse
     * @param version
     *                      Version of the Protocol
     * @param config
     *                      A Config used in the current context
     */
    public ChangeCipherSpecParser(int startposition, byte[] array, ProtocolVersion version, Config config) {
        super(startposition, array, version, config);
    }

    @Override
    protected ChangeCipherSpecMessage parseMessageContent() {
        LOGGER.debug("Parsing ChangeCipherSpecMessage");
        ChangeCipherSpecMessage msg = new ChangeCipherSpecMessage();
        parseCcsProtocolType(msg);
        return msg;
    }

    /**
     * Reads the next bytes as the CcsProtocolType and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCcsProtocolType(ChangeCipherSpecMessage msg) {
        msg.setCcsProtocolType(parseByteArrayField(ChangeCipherSpecByteLength.TYPE_LENGTH));
        LOGGER.debug("CcsProtocolType: " + ArrayConverter.bytesToHexString(msg.getCcsProtocolType().getValue()));
    }

}
