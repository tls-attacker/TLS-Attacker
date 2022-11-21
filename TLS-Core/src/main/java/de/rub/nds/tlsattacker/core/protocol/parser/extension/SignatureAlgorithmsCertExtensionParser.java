/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAlgorithmsCertExtensionParser extends ExtensionParser<SignatureAlgorithmsCertExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureAlgorithmsCertExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(SignatureAlgorithmsCertExtensionMessage msg) {
        parseSignatureAndHashAlgorithmsLength(msg);
        parseSignatureAndHashAlgorithms(msg);
    }

    @Override
    protected SignatureAlgorithmsCertExtensionMessage createExtensionMessage() {
        return new SignatureAlgorithmsCertExtensionMessage();
    }

    /**
     * Reads the next bytes as the signatureAndHandshakeAlgorithmsLength of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureAndHashAlgorithmsLength(SignatureAlgorithmsCertExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithmsLength(parseIntField(ExtensionByteLength.SIGNATURE_ALGORITHMS_CERT_LENGTH));
        LOGGER.debug("SignatureAndHashAlgorithmsLength: " + msg.getSignatureAndHashAlgorithmsLength().getValue());
    }

    /**
     * Reads the next bytes as the signatureAndHandshakeAlgorithms of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureAndHashAlgorithms(SignatureAlgorithmsCertExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithms(parseByteArrayField(msg.getSignatureAndHashAlgorithmsLength().getValue()));
        LOGGER.debug("SignatureAndHashAlgorithms: "
            + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithms().getValue()));
    }
}
