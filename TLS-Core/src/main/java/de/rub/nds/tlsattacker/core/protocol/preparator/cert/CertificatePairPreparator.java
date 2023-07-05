/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.cert;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificatePairPreparator extends Preparator<CertificatePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificatePair pair;

    public CertificatePairPreparator(Chooser chooser, CertificatePair pair) {
        super(chooser, pair);
        this.pair = pair;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing CertificatePair");
        prepareCertificate(pair);
        prepareCertificateLength(pair);
        if (pair.getExtensionsConfig() != null) {
            prepareExtensions(pair);
            prepareExtensionLength(pair);
        } else {
            pair.setExtensionsLength(0);
        }
    }

    private void prepareCertificate(CertificatePair pair) {
        pair.setCertificate(pair.getCertificateConfig());
        LOGGER.debug("Certificate: {}", pair.getCertificate().getValue());
    }

    private void prepareCertificateLength(CertificatePair pair) {
        pair.setCertificateLength(pair.getCertificate().getValue().length);
        LOGGER.debug("CertificateLength: " + pair.getCertificateLength().getValue());
    }

    private void prepareExtensions(CertificatePair pair) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        if (pair.getExtensionsConfig() != null) {
            for (ExtensionMessage extensionMessage : pair.getExtensionsConfig()) {
                extensionMessage.getPreparator(chooser.getContext().getTlsContext()).prepare();
                try {
                    stream.write(extensionMessage.getExtensionBytes().getValue());
                } catch (IOException ex) {
                    throw new PreparationException("Could not write ExtensionBytes to byte[]", ex);
                }
            }
            pair.setExtensions(stream.toByteArray());
        }
        LOGGER.debug("ExtensionBytes: {}", pair.getExtensions().getValue());
    }

    private void prepareExtensionLength(CertificatePair pair) {
        pair.setExtensionsLength(pair.getExtensions().getValue().length);
        LOGGER.debug("ExtensionLength: " + pair.getExtensionsLength().getValue());
    }
}
