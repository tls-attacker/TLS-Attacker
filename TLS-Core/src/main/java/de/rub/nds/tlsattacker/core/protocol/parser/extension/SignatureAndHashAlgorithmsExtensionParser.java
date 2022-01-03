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
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAndHashAlgorithmsExtensionParser
    extends ExtensionParser<SignatureAndHashAlgorithmsExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureAndHashAlgorithmsExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(SignatureAndHashAlgorithmsExtensionMessage msg) {
        parseSignatureAndHashAlgorithmsLength(msg);
        parseSignatureAndHashAlgorithms(msg);
    }

    @Override
    protected SignatureAndHashAlgorithmsExtensionMessage createExtensionMessage() {
        return new SignatureAndHashAlgorithmsExtensionMessage();
    }

    /**
     * Reads the next bytes as the signatureAndHandshakeAlgorithmsLength of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureAndHashAlgorithmsLength(SignatureAndHashAlgorithmsExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithmsLength(parseIntField(ExtensionByteLength.SIGNATURE_AND_HASH_ALGORITHMS));
        LOGGER.debug("SignatureAndHashAlgorithmsLength: " + msg.getSignatureAndHashAlgorithmsLength().getValue());
    }

    /**
     * Reads the next bytes as the signatureAndHandshakeAlgorithms of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureAndHashAlgorithms(SignatureAndHashAlgorithmsExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithms(parseByteArrayField(msg.getSignatureAndHashAlgorithmsLength().getValue()));
        LOGGER.debug("SignatureAndHashAlgorithms: "
            + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithms().getValue()));
    }
}
