/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
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
     *            Position in the array where the ClientKeyExchangeParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ClientKeyExchangeParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public SrpClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
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
     * Reads the next bytes as the PublicKeyLength and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePublicKeyLength(SrpClientKeyExchangeMessage message) {
        message.setPublicKeyLength(parseIntField(HandshakeByteLength.SRP_PUBLICKEY_LENGTH));
        LOGGER.debug("PublicKeyLength: " + message.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the PublicKey and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePublicKey(SrpClientKeyExchangeMessage message) {
        message.setPublicKey(parseByteArrayField(message.getPublicKeyLength().getValue()));
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(message.getPublicKey().getValue()));
    }
}
