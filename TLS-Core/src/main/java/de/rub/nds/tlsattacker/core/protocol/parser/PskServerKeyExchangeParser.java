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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskServerKeyExchangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskServerKeyExchangeParser extends ServerKeyExchangeParser<PskServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ProtocolVersion version;

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the ServerKeyExchangeParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ServerKeyExchangeParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public PskServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version);
        this.version = version;
    }

    @Override
    protected void parseHandshakeMessageContent(PskServerKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKECDHEServerKeyExchangeMessage");
        parsePskIdentityHintLength(msg);
        parsePskIdentityHint(msg);
    }

    @Override
    protected PskServerKeyExchangeMessage createHandshakeMessage() {
        return new PskServerKeyExchangeMessage();
    }

    private void parsePskIdentityHintLength(PskServerKeyExchangeMessage msg) {
        msg.setIdentityHintLength(parseIntField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("SerializedPSK-IdentityLength: " + msg.getIdentityHintLength().getValue());
    }

    /**
     * Reads the next bytes as the PSKIdentityHint and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentityHint(PskServerKeyExchangeMessage msg) {
        msg.setIdentityHint(parseByteArrayField(msg.getIdentityHintLength().getValue()));
        LOGGER.debug("SerializedPSK-Identity: " + ArrayConverter.bytesToHexString(msg.getIdentityHint().getValue()));
    }
}
