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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.SrpClientKeyExchangeMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrpClientKeyExchangeParser
        extends ClientKeyExchangeParser<SrpClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public SrpClientKeyExchangeParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(SrpClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing SRPClientKeyExchangeMessage");
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
    }

    /**
     * Reads the next bytes as the PublicKeyLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parsePublicKeyLength(SrpClientKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.SRP_PUBLICKEY_LENGTH));
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the PublicKey and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parsePublicKey(SrpClientKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("PublicKey: {}", msg.getPublicKey().getValue());
    }
}
