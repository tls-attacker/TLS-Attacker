/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAndHashAlgorithmsExtensionParser extends
        ExtensionParser<SignatureAndHashAlgorithmsExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureAndHashAlgorithmsExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
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
     * Reads the next bytes as the signatureAndHandshakeAlgorithmsLength of the
     * Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSignatureAndHashAlgorithmsLength(SignatureAndHashAlgorithmsExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithmsLength(parseIntField(ExtensionByteLength.SIGNATURE_AND_HASH_ALGORITHMS));
        LOGGER.debug("SignatureAndHashAlgorithmsLength: " + msg.getSignatureAndHashAlgorithmsLength().getValue());
    }

    /**
     * Reads the next bytes as the signatureAndHandshakeAlgorithms of the
     * Extension and writes them in the message
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
