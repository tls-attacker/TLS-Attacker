/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateVerifyParser extends HandshakeMessageParser<CertificateVerifyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext The current tlsContext
     */
    public CertificateVerifyParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(CertificateVerifyMessage msg) {
        LOGGER.debug("Parsing CertificateVerifyMessage");
        if (getVersion() == ProtocolVersion.TLS12
                || getVersion() == ProtocolVersion.DTLS12
                || getVersion().isTLS13()) {
            parseSignatureHashAlgorithm(msg);
        }
        parseSignatureLength(msg);
        parseSignature(msg);
    }

    /**
     * Reads the next bytes as the SignatureHashAlgorithm and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureHashAlgorithm(CertificateVerifyMessage msg) {
        msg.setSignatureHashAlgorithm(
                parseByteArrayField(HandshakeByteLength.SIGNATURE_HASH_ALGORITHM));
        LOGGER.debug("SignatureHashAlgorithm: {}", msg.getSignatureHashAlgorithm().getValue());
    }

    /**
     * Reads the next bytes as the SignatureLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureLength(CertificateVerifyMessage msg) {
        msg.setSignatureLength(parseIntField(HandshakeByteLength.SIGNATURE_LENGTH));
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    /**
     * Reads the next bytes as the Signature and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignature(CertificateVerifyMessage msg) {
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("signature: {}", msg.getSignature().getValue());
    }
}
