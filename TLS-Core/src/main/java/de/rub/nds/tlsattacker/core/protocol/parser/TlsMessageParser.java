/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import java.io.InputStream;

/**
 * An abstract Parser class for ProtocolMessages
 *
 */
public abstract class TlsMessageParser<Message extends TlsMessage> extends ProtocolMessageParser<Message> {

    private final ProtocolVersion version;

    /**
     * Constructor for the Parser class
     *
     * @param message
     * @param stream
     * @param version
     *                Version of the Protocol
     * @param config
     *                A Config used in the current context
     */
    public TlsMessageParser(InputStream stream, ProtocolVersion version, Config config) {
        super(stream, config);
        this.version = version;
    }

    protected ProtocolVersion getVersion() {
        return version;
    }

}
