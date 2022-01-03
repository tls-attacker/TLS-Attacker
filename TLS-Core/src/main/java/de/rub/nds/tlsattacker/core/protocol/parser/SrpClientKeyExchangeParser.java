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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SrpClientKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SrpClientKeyExchangeParser extends ClientKeyExchangeParser<SrpClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *                      Position in the array where the ClientKeyExchangeParser is supposed to start parsing
     * @param array
     *                      The byte[] which the ClientKeyExchangeParser is supposed to parse
     * @param version
     *                      Version of the Protocol
     * @param config
     *                      A Config used in the current context
     */
    public SrpClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version, Config config) {
        super(startposition, array, version, config);
    }

    @Override
    protected void parseHandshakeMessageContent(SrpClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing SRPClientKeyExchangeMessage");
        parsePublicKeyLength(msg);
        parsePublicKey(msg);
    }

    @Override
    protected SrpClientKeyExchangeMessage createHandshakeMessage() {
        return new SrpClientKeyExchangeMessage();
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
