/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageParser<T extends ProtocolMessage> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();
    protected final Config config;

    public ProtocolMessageParser(InputStream stream, Config config) {
        super(stream);
        this.config = config;
    }

    @Override
    public final T parse() {
        T msg = parseMessageContent();
        return msg;
    }

    protected abstract T parseMessageContent();


    protected Config getConfig() {
        return config;
    }
}
