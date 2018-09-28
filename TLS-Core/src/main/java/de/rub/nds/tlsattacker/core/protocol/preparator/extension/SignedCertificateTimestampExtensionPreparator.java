/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignedCertificateTimestampExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignedCertificateTimestampExtensionPreparator extends
        ExtensionPreparator<SignedCertificateTimestampExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SignedCertificateTimestampExtensionMessage message;

    public SignedCertificateTimestampExtensionPreparator(Chooser chooser,
            SignedCertificateTimestampExtensionMessage message, SignedCertificateTimestampExtensionSerializer serializer) {
        super(chooser, message, serializer);
        this.message = message;
    }

    /**
     * Parses a SignedCertificateTimestampExtensionMessage of a TLSContext.
     */
    @Override
    public void prepareExtensionContent() {
        message.setSignedTimestamp(chooser.getConfig().getDefaultSignedCertificateTimestamp());
        LOGGER.debug("Prepared the SignedCertificateTimestapExtension with timestamp length "
                + message.getSignedTimestamp().getValue().length);
    }

}
