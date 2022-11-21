/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;

/**
 * An abstract Parser class for ProtocolMessages
 *
 * @param <T>
 *            Type of the HandshakeMessages to parse
 */
public abstract class TlsMessageParser<T extends TlsMessage> extends ProtocolMessageParser<T> {

    private final ProtocolVersion version;

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *                Position in the array where the ProtocolMessageParser is supposed to start parsing
     * @param array
     *                The byte[] which the ProtocolMessageParser is supposed to parse
     * @param version
     *                Version of the Protocol
     * @param config
     *                A Config used in the current context
     */
    public TlsMessageParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, config);
        this.version = version;
    }

    protected ProtocolVersion getVersion() {
        return version;
    }

}
