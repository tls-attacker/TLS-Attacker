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
import de.rub.nds.tlsattacker.core.protocol.message.PSKRSAClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.parser.Parser.LOGGER;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKRSAClientKeyExchangeParser extends ClientKeyExchangeParser<PSKRSAClientKeyExchangeMessage> {
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
    public PSKRSAClientKeyExchangeParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    protected void parseHandshakeMessageContent(PSKRSAClientKeyExchangeMessage msg) {
        LOGGER.debug("Parsing PSKClientKeyExchangeMessage");
        parsePskIdentityLength(msg);
        parsePskIdentity(msg);
        parseEncryptedPreMasterSecretLength(msg);
        parseEncryptedPreMasterSecret(msg);
    }

    @Override
    protected PSKRSAClientKeyExchangeMessage createHandshakeMessage() {
        return new PSKRSAClientKeyExchangeMessage();
    }

    /**
     * Reads the next bytes as the SerializedPSKIdentityLength and writes them
     * in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentityLength(PSKRSAClientKeyExchangeMessage msg) {
        msg.setIdentityLength(parseByteArrayField(HandshakeByteLength.PSK_IDENTITY_LENGTH));
        LOGGER.debug("PSK-IdentityLength: " + msg.getIdentityLength().getValue());
    }

    /**
     * Reads the next bytes as the SerializedPSKIdentity and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parsePskIdentity(PSKRSAClientKeyExchangeMessage msg) {
        msg.setIdentity(parseByteArrayField(ArrayConverter.bytesToInt(msg.getIdentityLength().getValue())));
        LOGGER.debug("PSK-Identity: " + ArrayConverter.bytesToHexString(msg.getIdentity().getValue()));
    }

    private void parseEncryptedPreMasterSecret(PSKRSAClientKeyExchangeMessage msg) {
        msg.getComputations().setEncryptedPremasterSecret(
                parseByteArrayField(HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH));
        LOGGER.debug("EncryptedPreMasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getEncryptedPremasterSecret().getValue()));
    }

    private void parseEncryptedPreMasterSecretLength(PSKRSAClientKeyExchangeMessage msg) {
        msg.getComputations().setEncryptedPremasterSecretLength(parseByteArrayField(HandshakeByteLength.LENGTH_FIELD));
        LOGGER.debug("EncryptedPreMasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getEncryptedPremasterSecret().getValue()));
    }
}
