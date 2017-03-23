/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RSAClientKeyExchangeParser extends ClientKeyExchangeParser<RSAClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    /**
     * Constructor for the Parser class
     *
     * @param startposition  
     *            Position in the array where the ClientKeyExchangeParser is supposed
     *            to start parsing
     * @param array
     *            The byte[] which the ClientKeyExchangeParser is supposed to parse
     * @param version
     *            Version of the Protocol
     */ 
    public RSAClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected void parseHandshakeMessageContent(RSAClientKeyExchangeMessage msg) {
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
    }

    @Override
    protected RSAClientKeyExchangeMessage createHandshakeMessage() {
        return new RSAClientKeyExchangeMessage();
    }

    /**
     * Reads the next bytes as the SerializedPublicKeyLength and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKeyLength(RSAClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPublicKey and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSerializedPublicKey(RSAClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKey(parseByteArrayField(msg.getSerializedPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: " + Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }

}
