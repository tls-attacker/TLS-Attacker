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
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;

public class CertificateVerifyMessageParser extends HandshakeMessageParser<CertificateVerifyMessage> {

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the HandshakeMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the HandshakeMessageParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public CertificateVerifyMessageParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.CERTIFICATE_VERIFY, version);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateVerifyMessage msg) {
        LOGGER.debug("Parsing CertificateVerifyMessage");
        parseSignatureHashAlgorithm(msg);
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    @Override
    protected CertificateVerifyMessage createHandshakeMessage() {
        return new CertificateVerifyMessage();
    }

    /**
     * Reads the next bytes as the SignatureHashAlgorithm and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureHashAlgorithm(CertificateVerifyMessage msg) {
        msg.setSignatureHashAlgorithm(parseByteArrayField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHM));
        LOGGER.debug("SignatureHashAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureHashAlgorithm().getValue()));
    }

    /**
     * Reads the next bytes as the SignatureLength and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureLength(CertificateVerifyMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Reads the next bytes as the Signature and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignature(CertificateVerifyMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signatur: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

}
