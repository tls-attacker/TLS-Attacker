/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignedCertificateTimestampExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SignedCertificateTimestampExtensionHandler
        extends ExtensionHandler<SignedCertificateTimestampExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor
     *
     * @param tlsContext A Chooser
     */
    public SignedCertificateTimestampExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    /**
     * Parses the content of a SignedCertificateTimestampExtensionMessage to the actual Chooser
     *
     * @param message A SingedCertificateTimestampExtensionMessage
     */
    @Override
    public void adjustTLSExtensionContext(SignedCertificateTimestampExtensionMessage message) {
        if (message.getExtensionLength().getValue() > 65535) {
            LOGGER.warn(
                    "The SingedCertificateTimestamp length shouldn't exceed 2 bytes as defined in RFC 6962. "
                            + "Length was "
                            + message.getExtensionLength().getValue());
        }
        tlsContext.setSignedCertificateTimestamp(message.getSignedTimestamp().getValue());
        LOGGER.debug(
                "The context SignedCertificateTimestamp was set to {}",
                message.getSignedTimestamp());
    }
}
