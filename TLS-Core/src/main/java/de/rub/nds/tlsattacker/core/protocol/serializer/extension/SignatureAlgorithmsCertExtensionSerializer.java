/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAlgorithmsCertExtensionSerializer
        extends ExtensionSerializer<SignatureAlgorithmsCertExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SignatureAlgorithmsCertExtensionMessage msg;

    public SignatureAlgorithmsCertExtensionSerializer(
            SignatureAlgorithmsCertExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing SignatureAlgorithmsCertExtensionMessage");
        writeSignatureAndHashAlgorithmsLength(msg);
        writeSignatureAndHashAlgorithms(msg);
        return getAlreadySerialized();
    }

    private void writeSignatureAndHashAlgorithmsLength(
            SignatureAlgorithmsCertExtensionMessage msg) {
        appendInt(
                msg.getSignatureAndHashAlgorithmsLength().getValue(),
                ExtensionByteLength.SIGNATURE_ALGORITHMS_CERT_LENGTH);
        LOGGER.debug(
                "SignatureAndHashAlgorithmsLength: "
                        + msg.getSignatureAndHashAlgorithmsLength().getValue());
    }

    private void writeSignatureAndHashAlgorithms(SignatureAlgorithmsCertExtensionMessage msg) {
        appendBytes(msg.getSignatureAndHashAlgorithms().getValue());
        LOGGER.debug(
                "SignatureAndHashAlgorithms: {}", msg.getSignatureAndHashAlgorithms().getValue());
    }
}
