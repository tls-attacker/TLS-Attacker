/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.tlsattacker.core.config.Config;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageParser<Message extends ProtocolMessage> extends Parser<Message> {

    private static final Logger LOGGER = LogManager.getLogger();
    protected final Config config;

    public ProtocolMessageParser(InputStream stream, Config config) {
        super(stream);
        this.config = config;
    }

    @Override
    public final void parse(Message message) {
        parseMessageContent(message);
    }

    protected abstract void parseMessageContent(Message message);

    protected Config getConfig() {
        return config;
    }
}
