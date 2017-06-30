/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SignatureAndHashAlgorithmsExtensionPreparator extends
        ExtensionPreparator<SignatureAndHashAlgorithmsExtensionMessage> {

    private final SignatureAndHashAlgorithmsExtensionMessage msg;

    public SignatureAndHashAlgorithmsExtensionPreparator(TlsContext context,
            SignatureAndHashAlgorithmsExtensionMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing SignatureAndHashAlgorithmsExtensionMessage");
        prepareSignatureAndHashAlgorithms(msg);
        prepareSignatureAndHashAlgorithmsLength(msg);
    }

    private void prepareSignatureAndHashAlgorithms(SignatureAndHashAlgorithmsExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithms(createSignatureAndHashAlgorithmsArray());
        LOGGER.debug("SignatureAndHashAlgorithms: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithms().getValue()));
    }

    private byte[] createSignatureAndHashAlgorithmsArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (SignatureAndHashAlgorithm algo : context.getConfig().getSupportedSignatureAndHashAlgorithms()) {
            try {
                stream.write(algo.getByteValue());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] of SignatureAndHashAlgorithms to Stream", ex);
            }
        }
        return stream.toByteArray();
    }

    private void prepareSignatureAndHashAlgorithmsLength(SignatureAndHashAlgorithmsExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithmsLength(msg.getSignatureAndHashAlgorithms().getValue().length);
        LOGGER.debug("SignatureAndHashAlgorithmsLength: " + msg.getSignatureAndHashAlgorithmsLength().getValue());
    }
}
