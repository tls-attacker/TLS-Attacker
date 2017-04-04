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

     /**
     * Constructor for the CertificateVerifyMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public CertificateVerifyMessageSerializer(CertificateVerifyMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeSignatureHashAlgorithm(msg);
        writeSignatureLength(msg);
        writeSignature(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the SignatureHashAlgorithm of the CertificateVerifyMessage into the final byte[]
     */
    private void writeSignatureHashAlgorithm(CertificateVerifyMessage msg) {
        appendBytes(msg.getSignatureHashAlgorithm().getValue());
        LOGGER.debug("SignatureHashAlgorithms: "+ Arrays.toString(msg.getSignatureHashAlgorithm().getValue()));
    }

    /**
     * Writes the SignatureLength of the CertificateVerifyMessage into the final byte[]
     */
    private void writeSignatureLength(CertificateVerifyMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), HandshakeByteLength.SIGNATURE_LENGTH);
        LOGGER.debug("SignatureLength: "+ msg.getSignatureLength().getValue());
    }

    /**
     * Writes the Signature of the CertificateVerifyMessage into the final byte[]
     */
    private void writeSignature(CertificateVerifyMessage msg) {
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: "+ Arrays.toString(msg.getSignature().getValue()));
    }

}
