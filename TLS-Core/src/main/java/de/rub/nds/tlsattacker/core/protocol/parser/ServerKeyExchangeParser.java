/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

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
                tlsContext.getChooser().getSelectedCipherSuite().getKeyExchangeAlgorithm();
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

    /**
     * Determines whether signature fields should be parsed based on the key exchange algorithm.
     *
     * <p>For anonymous key exchange algorithms (DH_ANON, ECDH_ANON), no signature should be parsed.
     * For all other algorithms, signatures are required.
     *
     * <p>If keyExchangeAlgorithm is null (which can happen in test scenarios where the cipher suite
     * context is not fully established), we assume it's a non-anonymous exchange that requires
     * signature parsing.
     *
     * @return true if signature fields should be parsed, false otherwise
     */
    protected boolean shouldParseSignature() {
        KeyExchangeAlgorithm keyExchangeAlgorithm = getKeyExchangeAlgorithm();

        if (keyExchangeAlgorithm == null) {
            return true;
        }

        return !keyExchangeAlgorithm.isAnon();
    }
}
