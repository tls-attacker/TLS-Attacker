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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownHandshakeParser extends HandshakeMessageParser<UnknownHandshakeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *                Position in the array where the HandshakeMessageParser is supposed to start parsing
     * @param array
     *                The byte[] which the HandshakeMessageParser is supposed to parse
     * @param version
     *                Version of the Protocol
     * @param config
     *                A Config used in the current context
     */
    public UnknownHandshakeParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, HandshakeMessageType.UNKNOWN, version, config);
    }

    @Override
    protected void parseHandshakeMessageContent(UnknownHandshakeMessage msg) {
        LOGGER.debug("Parsing UnknownHandshakeMessage");
        parseData(msg);
        LOGGER.warn(
            "Parsed UnknownHandshake Message: " + ArrayConverter.bytesToHexString(msg.getData().getValue(), false));

    }

    @Override
    protected UnknownHandshakeMessage createHandshakeMessage() {
        return new UnknownHandshakeMessage();
    }

    /**
     * Reads the next bytes as the Data and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseData(UnknownHandshakeMessage msg) {
        msg.setData(parseByteArrayField(msg.getLength().getValue()));
        LOGGER.debug("Data: " + ArrayConverter.bytesToHexString(msg.getData().getValue()));
    }
}
