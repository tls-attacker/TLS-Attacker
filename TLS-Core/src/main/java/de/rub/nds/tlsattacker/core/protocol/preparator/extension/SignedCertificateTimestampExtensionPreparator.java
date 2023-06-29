/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignedCertificateTimestampExtensionPreparator
        extends ExtensionPreparator<SignedCertificateTimestampExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SignedCertificateTimestampExtensionMessage message;

    public SignedCertificateTimestampExtensionPreparator(
            Chooser chooser, SignedCertificateTimestampExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    /** Parses a SignedCertificateTimestampExtensionMessage of a TLSContext. */
    @Override
    public void prepareExtensionContent() {
        message.setSignedTimestamp(chooser.getConfig().getDefaultSignedCertificateTimestamp());
        LOGGER.debug(
                "Prepared the SignedCertificateTimestampExtension with timestamp length "
                        + message.getSignedTimestamp().getValue().length);
    }
}
