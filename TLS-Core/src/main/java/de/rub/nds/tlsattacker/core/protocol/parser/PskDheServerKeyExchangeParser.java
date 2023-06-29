/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskDheServerKeyExchangeParser
        extends DHEServerKeyExchangeParser<PskDheServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public PskDheServerKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
        setKeyExchangeAlgorithm(KeyExchangeAlgorithm.DHE_PSK);
    }

    @Override
    public void parse(PskDheServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKDHEServerKeyExchangeMessage");
        parsePskIdentityHintLength(msg);
        parsePskIdentityHint(msg);
        super.parseDheParams(msg);
    }

    private void parsePskIdentityHintLength(PskDheServerKeyExchangeMessage msg) {
        msg.setIdentityHintLength(parseIntField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("SerializedPSL-IdentityLength: " + msg.getIdentityHintLength().getValue());
    }

    /**
     * Reads the next bytes as the PSKIdentityHint and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parsePskIdentityHint(PskDheServerKeyExchangeMessage msg) {
        msg.setIdentityHint(parseByteArrayField(msg.getIdentityHintLength().getValue()));
        LOGGER.debug("SerializedPSK-Identity: {}", msg.getIdentityHint().getValue());
    }
}
