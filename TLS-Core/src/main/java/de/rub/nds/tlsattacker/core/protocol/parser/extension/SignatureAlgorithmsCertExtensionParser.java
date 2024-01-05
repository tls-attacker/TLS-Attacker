/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAlgorithmsCertExtensionParser
        extends ExtensionParser<SignatureAlgorithmsCertExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureAlgorithmsCertExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    /**
     * Reads the next bytes as the signatureAndHandshakeAlgorithmsLength of the Extension and writes
     * them in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureAndHashAlgorithmsLength(
            SignatureAlgorithmsCertExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithmsLength(
                parseIntField(ExtensionByteLength.SIGNATURE_ALGORITHMS_CERT_LENGTH));
        LOGGER.debug(
                "SignatureAndHashAlgorithmsLength: "
                        + msg.getSignatureAndHashAlgorithmsLength().getValue());
    }

    /**
     * Reads the next bytes as the signatureAndHandshakeAlgorithms of the Extension and writes them
     * in the message
     *
     * @param msg Message to write in
     */
    private void parseSignatureAndHashAlgorithms(SignatureAlgorithmsCertExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithms(
                parseByteArrayField(msg.getSignatureAndHashAlgorithmsLength().getValue()));
        LOGGER.debug(
                "SignatureAndHashAlgorithms: {}", msg.getSignatureAndHashAlgorithms().getValue());
    }

    @Override
    public void parse(SignatureAlgorithmsCertExtensionMessage msg) {
        parseSignatureAndHashAlgorithmsLength(msg);
        parseSignatureAndHashAlgorithms(msg);
    }
}
