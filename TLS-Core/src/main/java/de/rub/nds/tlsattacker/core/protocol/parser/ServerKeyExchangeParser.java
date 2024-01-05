/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import java.io.InputStream;

/**
 * @param <T> The ServerKeyExchangeMessage that should be parsed
 */
public abstract class ServerKeyExchangeParser<T extends ServerKeyExchangeMessage>
        extends HandshakeMessageParser<T> {

    private KeyExchangeAlgorithm keyExchangeAlgorithm;

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public ServerKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
        this.keyExchangeAlgorithm =
                AlgorithmResolver.getKeyExchangeAlgorithm(
                        tlsContext.getChooser().getSelectedCipherSuite());
    }

    protected KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        return this.keyExchangeAlgorithm;
    }

    protected void setKeyExchangeAlgorithm(KeyExchangeAlgorithm keyExchangeAlgorithm) {
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    /**
     * Checks if the version is TLS12
     *
     * @return True if the used version is TLS12
     */
    protected boolean isTLS12() {
        return getVersion() == ProtocolVersion.TLS12;
    }

    /**
     * Checks if the version is DTLS12
     *
     * @return True if the used version is DTLS12
     */
    protected boolean isDTLS12() {
        return getVersion() == ProtocolVersion.DTLS12;
    }
}
