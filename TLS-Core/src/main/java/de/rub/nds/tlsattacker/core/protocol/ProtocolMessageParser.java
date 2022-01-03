/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageParser<T extends ProtocolMessage> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();
    protected final Config config;

    public ProtocolMessageParser(int startposition, byte[] array, Config config) {
        super(startposition, array);
        this.config = config;
    }

    @Override
    public final T parse() {
        T msg = parseMessageContent();
        parseCompleteResultingMessage(msg);
        return msg;
    }

    protected abstract T parseMessageContent();

    /**
     * Reads the next bytes as the CompleteResultingMessage and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCompleteResultingMessage(ProtocolMessage msg) {
        msg.setCompleteResultingMessage(getAlreadyParsed());
        LOGGER.debug(
            "CompleteResultMessage: " + ArrayConverter.bytesToHexString(msg.getCompleteResultingMessage().getValue()));
    }

    protected Config getConfig() {
        return config;
    }
}
