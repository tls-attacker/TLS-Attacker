/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

/**
 * @param <T>
 *            The ServerKeyExchangeMessage that should be parsed
 */
public abstract class ServerKeyExchangeParser<T extends ServerKeyExchangeMessage> extends HandshakeMessageParser<T> {

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                   Version of the Protocol
     * @param tlsContext
     *                   A Config used in the current context
     */
    public ServerKeyExchangeParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream, version, tlsContext);
    }

}
