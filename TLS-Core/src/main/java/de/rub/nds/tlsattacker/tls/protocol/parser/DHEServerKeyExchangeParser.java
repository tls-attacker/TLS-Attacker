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
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangeParser extends ServerKeyExchangeParser<DHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    private final ProtocolVersion version;

    public DHEServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version);
        this.version = version;
    }

    @Override
    protected void parseHandshakeMessageContent(DHEServerKeyExchangeMessage msg) {
        parsepLength(msg);
        parseP(msg);
        parsegLength(msg);
        parseG(msg);
        parseSerializedPublicKeyLength(msg);
        parseSerializedPublicKey(msg);
        if (isTLS12() || isDTLS12()) {
            parseHashAlgorithm(msg);
            parseSignatureAlgorithm(msg);
        }
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    @Override
    protected DHEServerKeyExchangeMessage createHandshakeMessage() {
        return new DHEServerKeyExchangeMessage();
    }

    private void parsepLength(DHEServerKeyExchangeMessage msg) {
        msg.setpLength(parseIntField(HandshakeByteLength.DH_P_LENGTH));
        LOGGER.debug("pLength: " + msg.getpLength().getValue());
    }

    private void parseP(DHEServerKeyExchangeMessage msg) {
        msg.setP(parseBigIntField(msg.getpLength().getValue()));
        LOGGER.debug("P: " + msg.getP().getValue());
    }

    private void parsegLength(DHEServerKeyExchangeMessage msg) {
        msg.setgLength(parseIntField(HandshakeByteLength.DH_G_LENGTH));
        LOGGER.debug("gLength: " + msg.getgLength().getValue());
    }

    private void parseG(DHEServerKeyExchangeMessage msg) {
        msg.setG(parseBigIntField(msg.getgLength().getValue()));
        LOGGER.debug("G: " + msg.getG().getValue());
    }

    private void parseSerializedPublicKeyLength(DHEServerKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.DH_PUBLICKEY_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    private void parseSerializedPublicKey(DHEServerKeyExchangeMessage msg) {
        msg.setSerializedPublicKey(parseByteArrayField(msg.getSerializedPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: " + Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }

    private boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    private boolean isDTLS12() {
        return version == ProtocolVersion.DTLS12;
    }

    private void parseHashAlgorithm(DHEServerKeyExchangeMessage msg) {
        msg.setHashAlgorithm(parseByteField(HandshakeByteLength.HASH));
        LOGGER.debug("HashAlgorithm: " + msg.getHashAlgorithm().getValue());
    }

    private void parseSignatureAlgorithm(DHEServerKeyExchangeMessage msg) {
        msg.setSignatureAlgorithm(parseByteField(HandshakeByteLength.SIGNATURE));
        LOGGER.debug("SignatureAlgorithm: " + msg.getSignatureAlgorithm().getValue());
    }

    private void parseSignatureLength(DHEServerKeyExchangeMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void parseSignature(DHEServerKeyExchangeMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + Arrays.toString(msg.getSignature().getValue()));
    }
}
