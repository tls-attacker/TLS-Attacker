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
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangeSerializer extends ServerKeyExchangeSerializer<DHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private DHEServerKeyExchangeMessage msg;

    public DHEServerKeyExchangeSerializer(DHEServerKeyExchangeMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        serializePLength(msg);
        serializeP(msg);
        serializegLength(msg);
        serializeG(msg);
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

    private void serializePLength(DHEServerKeyExchangeMessage msg) {
        appendInt(msg.getpLength().getValue(), HandshakeByteLength.DH_P_LENGTH);
        LOGGER.debug("pLength: "+ msg.getpLength().getValue());
    }

    private void serializeP(DHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getP().getByteArray());
        LOGGER.debug("P: "+ msg.getP().getValue());
    }

    private void serializegLength(DHEServerKeyExchangeMessage msg) {
        appendInt(msg.getgLength().getValue(), HandshakeByteLength.DH_G_LENGTH);
        LOGGER.debug("gLength: "+ msg.getgLength().getValue());
    }

    private void serializeG(DHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getG().getByteArray());
        LOGGER.debug("G: "+ msg.getG().getValue());
    }

    private void serializeSerializedPublicKeyLength(DHEServerKeyExchangeMessage msg) {
        appendInt(msg.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH);
        LOGGER.debug("SerializedPublicKeyLength: "+ msg.getSerializedPublicKeyLength().getValue());
    }

    private void serializeSerializedPublicKey(DHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getSerializedPublicKey().getValue());
        LOGGER.debug("SerializedPublicKey: "+ Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }

    private void serializeHashAlgorithm(DHEServerKeyExchangeMessage msg) {
        appendByte(msg.getHashAlgorithm().getValue());
        LOGGER.debug("HaslAlgorithm: "+ msg.getHashAlgorithm().getValue());
    }

    private void serializeSignatureAlgorithm(DHEServerKeyExchangeMessage msg) {
        appendByte(msg.getSignatureAlgorithm().getValue());
        LOGGER.debug("SignatureAlgorithm: "+ msg.getSignatureAlgorithm().getValue());
    }

    private boolean isTLS12() {
        return version == ProtocolVersion.TLS12;
    }

    private boolean isDTLS12() {
        return version == ProtocolVersion.DTLS12;
    }

    private void serializeSignatureLength(DHEServerKeyExchangeMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        LOGGER.debug("SignatureLength: "+ msg.getSignatureLength().getValue());
    }

    private void serializeSignature(DHEServerKeyExchangeMessage msg) {
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: "+ Arrays.toString(msg.getSignature().getValue()));
    }

}
