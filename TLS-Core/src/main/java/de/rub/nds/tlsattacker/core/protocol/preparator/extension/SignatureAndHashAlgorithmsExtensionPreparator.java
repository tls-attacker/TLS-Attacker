/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SignatureAndHashAlgorithmsExtensionPreparator extends
        ExtensionPreparator<SignatureAndHashAlgorithmsExtensionMessage> {

    private final SignatureAndHashAlgorithmsExtensionMessage message;

    public SignatureAndHashAlgorithmsExtensionPreparator(Chooser chooser,
            SignatureAndHashAlgorithmsExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        prepareSignatureAndHashAlgorithms();
        message.setSignatureAndHashAlgorithmsLength(message.getSignatureAndHashAlgorithms().getValue().length);
    }

    private void prepareSignatureAndHashAlgorithms() {
        message.setSignatureAndHashAlgorithms(createSignatureAndHashAlgorithmsArray());
    }

    private byte[] createSignatureAndHashAlgorithmsArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (SignatureAndHashAlgorithm algo : chooser.getConfig().getSupportedSignatureAndHashAlgorithms()) {
            try {
                stream.write(algo.getByteValue());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] of SignatureAndHashAlgorithms to Stream", ex);
            }
        }
        return stream.toByteArray();
    }
}
