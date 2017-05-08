/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SignedCertificateTimestampExtensionPreparator extends
        ExtensionPreparator<SignedCertificateTimestampExtensionMessage> {

    private final SignedCertificateTimestampExtensionMessage message;

    /**
     * Constructor
     * 
     * @param context
     * @param message
     */
    public SignedCertificateTimestampExtensionPreparator(TlsContext context,
            SignedCertificateTimestampExtensionMessage message) {
        super(context, message);
        this.message = message;
    }

    /**
     * Parses a SignedCertificateTimestampExtensionMessage of a TLSContext.
     */
    @Override
    public void prepareExtensionContent() {
        message.setSignedTimestamp(context.getConfig().getSignedCertificateTimestamp());
        LOGGER.debug("Prepared the SignedCertificateTimestapExtension with timestamp length "
                + message.getSignedTimestamp().getValue().length);
    }

}
