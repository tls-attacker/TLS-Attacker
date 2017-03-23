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
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHEServerKeyExchangeParser extends ServerKeyExchangeParser<ECDHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    private final ProtocolVersion version;

    public ECDHEServerKeyExchangeParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.SERVER_KEY_EXCHANGE, version);
        this.version = version;
    }

    @Override
    protected void parseHandshakeMessageContent(ECDHEServerKeyExchangeMessage msg) {
        parseCurveType(msg);
        parseNamedCurve(msg);
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
    protected ECDHEServerKeyExchangeMessage createHandshakeMessage() {
        return new ECDHEServerKeyExchangeMessage();
    }

    private void parseCurveType(ECDHEServerKeyExchangeMessage msg) {
        msg.setCurveType(parseByteField(HandshakeByteLength.ELLIPTIC_CURVE));
        LOGGER.debug("CurveType: " + msg.getCurveType().getValue());
    }

    private void parseNamedCurve(ECDHEServerKeyExchangeMessage msg) {
        msg.setNamedCurve(parseByteArrayField(NamedCurve.LENGTH));
        LOGGER.debug("NamedCurve: " + Arrays.toString(msg.getNamedCurve().getValue()));
    }

    private void parseSerializedPublicKeyLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(parseIntField(HandshakeByteLength.ECDHE_PARAM_LENGTH));
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    private void parseSerializedPublicKey(ECDHEServerKeyExchangeMessage msg) {
        msg.setSerializedPublicKey(parseByteArrayField(msg.getSerializedPublicKeyLength().getValue()));
        LOGGER.debug("SerializedPublicKey: " + Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }

    private boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    private boolean isDTLS12() {
        return version == ProtocolVersion.DTLS12;
    }

    private void parseHashAlgorithm(ECDHEServerKeyExchangeMessage msg) {
        msg.setHashAlgorithm(parseByteField(HandshakeByteLength.HASH));
        LOGGER.debug("HashAlgorithm: " + msg.getHashAlgorithm().getValue());
    }

    private void parseSignatureAlgorithm(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignatureAlgorithm(parseByteField(HandshakeByteLength.SIGNATURE));
        LOGGER.debug("SignatureAlgorithm: " + msg.getSignatureAlgorithm().getValue());
    }

    private void parseSignatureLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void parseSignature(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + Arrays.toString(msg.getSignature().getValue()));
    }
}
