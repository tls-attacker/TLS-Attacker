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
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateVerifyMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateVerifyMessageSerializer extends HandshakeMessageSerializer<CertificateVerifyMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private final CertificateVerifyMessage msg;

    public CertificateVerifyMessageSerializer(CertificateVerifyMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        serializeSignatureHashAlgorithm(msg);
        serializeSignatureLength(msg);
        serializeSignature(msg);
        return getAlreadySerialized();
    }

    private void serializeSignatureHashAlgorithm(CertificateVerifyMessage msg) {
        appendBytes(msg.getSignatureHashAlgorithm().getValue());
        LOGGER.debug("SignatureHashAlgorithms: "+ Arrays.toString(msg.getSignatureHashAlgorithm().getValue()));
    }

    private void serializeSignatureLength(CertificateVerifyMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        LOGGER.debug("SignatureLength: "+ msg.getSignatureLength().getValue());
    }

    private void serializeSignature(CertificateVerifyMessage msg) {
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: "+ Arrays.toString(msg.getSignature().getValue()));
    }

}
