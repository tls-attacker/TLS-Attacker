/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SignatureAndHashAlgorithmsExtensionPreparator extends
        ExtensionPreparator<SignatureAndHashAlgorithmsExtensionMessage> {

    private final SignatureAndHashAlgorithmsExtensionMessage message;

    public SignatureAndHashAlgorithmsExtensionPreparator(TlsContext context,
            SignatureAndHashAlgorithmsExtensionMessage message) {
        super(context, message);
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
        for (SignatureAndHashAlgorithm algo : context.getConfig().getSupportedSignatureAndHashAlgorithms()) {
            try {
                stream.write(algo.getByteValue());
            } catch (IOException ex) {
                throw new PreparationException("Could not write byte[] of SignatureAndHashAlgorithms to Stream", ex);
            }
        }
        return stream.toByteArray();
    }
}
