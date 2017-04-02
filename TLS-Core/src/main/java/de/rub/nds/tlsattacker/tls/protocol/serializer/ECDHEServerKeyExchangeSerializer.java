/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHEServerKeyExchangeMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHEServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<ECDHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private final ECDHEServerKeyExchangeMessage msg;

    public ECDHEServerKeyExchangeSerializer(ECDHEServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        serializeCurveType(msg);
        serializeNamedCurve(msg);
        serializeSerializedPublicKeyLength(msg);
        serializeSerializedPublicKey(msg);
        if (isTLS12() || isDTLS12()) {
            serializeHashAlgorithm(msg);
            serializeSignatureAlgorithm(msg);
        }
        serializeSignatureLength(msg);
        serializeSignature(msg);
        return getAlreadySerialized();
    }

    private void serializeCurveType(ECDHEServerKeyExchangeMessage msg) {
        appendByte(msg.getCurveType().getValue());
        LOGGER.debug("CurveType: "+ msg.getCurveType().getValue());
    }

    private void serializeNamedCurve(ECDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getNamedCurve().getValue());
        LOGGER.debug("NamedCurve: "+ Arrays.toString(msg.getNamedCurve().getValue()));
    }

    private void serializeSerializedPublicKeyLength(ECDHEServerKeyExchangeMessage msg) {
        appendInt(msg.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.ECDHE_PARAM_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: "+ msg.getSerializedPublicKeyLength().getValue());
    }

    private void serializeSerializedPublicKey(ECDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getSerializedPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: "+ Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }
    
    private boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    private boolean isDTLS12() {
        return version == ProtocolVersion.DTLS12;
    }

    private void serializeHashAlgorithm(ECDHEServerKeyExchangeMessage msg) {
        appendByte(msg.getHashAlgorithm().getValue());
        LOGGER.debug("HashAlgorithm: "+ msg.getHashAlgorithm().getValue());
    }

    private void serializeSignatureAlgorithm(ECDHEServerKeyExchangeMessage msg) {
        appendByte(msg.getSignatureAlgorithm().getValue());
        LOGGER.debug("SignatureAlgorithm: "+ msg.getSignatureAlgorithm().getValue());
    }

    private void serializeSignatureLength(ECDHEServerKeyExchangeMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        LOGGER.debug("SignatureLength: "+ msg.getSignatureLength().getValue());
    }

    private void serializeSignature(ECDHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: "+ Arrays.toString(msg.getSignature().getValue()));
    }

}
