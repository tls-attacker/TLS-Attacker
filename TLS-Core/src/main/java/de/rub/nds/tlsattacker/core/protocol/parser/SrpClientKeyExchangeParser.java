/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SrpClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;

public class SrpClientKeyExchangeParser extends ClientKeyExchangeParser<SrpClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param version
     *                Version of the Protocol
     * @param tlsContext
     *
     */
    public SrpClientKeyExchangeParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream, version, tlsContext);
    }

    @Override
    protected void parseHandshakeMessageContent(SrpClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing SRPClientKeyExchangeMessage");
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
    }

    /**
     * Reads the next bytes as the PublicKeyLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePublicKeyLength(SrpClientKeyExchangeMessage msg) {
        msg.setPublicKeyLength(parseIntField(HandshakeByteLength.SRP_PUBLICKEY_LENGTH));
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the PublicKey and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePublicKey(SrpClientKeyExchangeMessage msg) {
        msg.setPublicKey(parseByteArrayField(msg.getPublicKeyLength().getValue()));
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }
}
