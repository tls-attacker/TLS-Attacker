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
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An abstract Parser class for ProtocolMessages
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 *            Type of the HandshakeMessages to parse
 */
public abstract class ProtocolMessageParser<T extends ProtocolMessage> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger(ProtocolMessageParser.class);

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the ProtocolMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ProtocolMessageParser is supposed to
     *            parse
     *
     */
    public ProtocolMessageParser(int pointer, byte[] array) {
        super(pointer, array);
    }

    @Override
    public final T parse() {
        T msg = parseMessageContent();
        setCompleteResultingMessage(msg);
        return msg;
    }

    protected abstract T parseMessageContent();

    private void setCompleteResultingMessage(ProtocolMessage message) {
        message.setCompleteResultingMessage(getAlreadyParsed());
    }
}
