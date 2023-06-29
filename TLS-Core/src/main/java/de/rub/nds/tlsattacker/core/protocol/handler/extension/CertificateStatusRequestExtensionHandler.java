/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static de.rub.nds.tlsattacker.transport.ConnectionEndType.CLIENT;

import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusRequestExtensionHandler
        extends ExtensionHandler<CertificateStatusRequestExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusRequestExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(CertificateStatusRequestExtensionMessage message) {
        if (tlsContext.getTalkingConnectionEndType() == CLIENT) {
            tlsContext.setCertificateStatusRequestExtensionRequestType(
                    CertificateStatusRequestType.getCertificateStatusRequestType(
                            message.getCertificateStatusRequestType().getValue()));
            LOGGER.debug(
                    "Adjusted the Certificate Status Request Type in the TLSContext to "
                            + tlsContext.getCertificateStatusRequestExtensionRequestType());
            tlsContext.setCertificateStatusRequestExtensionRequestExtension(
                    message.getRequestExtension().getValue());
            LOGGER.debug(
                    "Adjusted the Certificate Status Request Request Extension to {}",
                    tlsContext.getCertificateStatusRequestExtensionRequestExtension());
            tlsContext.setCertificateStatusRequestExtensionResponderIDList(
                    message.getResponderIDList().getValue());
            LOGGER.debug(
                    "Adjusted the Certificate Status Request Responder ID List to {}",
                    tlsContext.getCertificateStatusRequestExtensionResponderIDList());
        }
    }
}
