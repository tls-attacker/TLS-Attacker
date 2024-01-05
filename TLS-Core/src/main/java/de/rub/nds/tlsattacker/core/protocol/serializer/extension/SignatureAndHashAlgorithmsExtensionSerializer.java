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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAndHashAlgorithmsExtensionSerializer
        extends ExtensionSerializer<SignatureAndHashAlgorithmsExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SignatureAndHashAlgorithmsExtensionMessage msg;

    public SignatureAndHashAlgorithmsExtensionSerializer(
            SignatureAndHashAlgorithmsExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing SignatureAndHashAlgorithmsExtensionMessage");
        writeSignatureAndHashAlgorithmsLength(msg);
        writeSignatureAndHashAlgorithms(msg);
        return getAlreadySerialized();
    }

    private void writeSignatureAndHashAlgorithmsLength(
            SignatureAndHashAlgorithmsExtensionMessage msg) {
        appendInt(
                msg.getSignatureAndHashAlgorithmsLength().getValue(),
                ExtensionByteLength.SIGNATURE_AND_HASH_ALGORITHMS);
        LOGGER.debug(
                "SignatureAndHashAlgorithmsLength: "
                        + msg.getSignatureAndHashAlgorithmsLength().getValue());
    }

    private void writeSignatureAndHashAlgorithms(SignatureAndHashAlgorithmsExtensionMessage msg) {
        appendBytes(msg.getSignatureAndHashAlgorithms().getValue());
        LOGGER.debug(
                "SignatureAndHashAlgorithms: {}", msg.getSignatureAndHashAlgorithms().getValue());
    }
}
