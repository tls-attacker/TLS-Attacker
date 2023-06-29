/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignatureAlgorithmsCertExtensionPreparator
        extends ExtensionPreparator<SignatureAlgorithmsCertExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SignatureAlgorithmsCertExtensionMessage msg;

    public SignatureAlgorithmsCertExtensionPreparator(
            Chooser chooser, SignatureAlgorithmsCertExtensionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing SignatureAlgorithmsCertExtensionMessage");
        prepareSignatureAndHashAlgorithms(msg);
        prepareSignatureAndHashAlgorithmsLength(msg);
    }

    private void prepareSignatureAndHashAlgorithms(SignatureAlgorithmsCertExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithms(createSignatureAndHashAlgorithmsArray());
        LOGGER.debug(
                "SignatureAndHashAlgorithms: {}", msg.getSignatureAndHashAlgorithms().getValue());
    }

    private byte[] createSignatureAndHashAlgorithmsArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmList;
        if (chooser.getContext().getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            signatureAndHashAlgorithmList =
                    chooser.getConfig().getDefaultServerSupportedCertificateSignAlgorithms();
        } else {
            signatureAndHashAlgorithmList =
                    chooser.getConfig().getDefaultClientSupportedCertificateSignAlgorithms();
        }

        for (SignatureAndHashAlgorithm algo : signatureAndHashAlgorithmList) {
            try {
                stream.write(algo.getByteValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not write byte[] of SignatureAndHashAlgorithms to Stream", ex);
            }
        }
        return stream.toByteArray();
    }

    private void prepareSignatureAndHashAlgorithmsLength(
            SignatureAlgorithmsCertExtensionMessage msg) {
        msg.setSignatureAndHashAlgorithmsLength(
                msg.getSignatureAndHashAlgorithms().getValue().length);
        LOGGER.debug(
                "SignatureAndHashAlgorithmsLength: "
                        + msg.getSignatureAndHashAlgorithmsLength().getValue());
    }
}
