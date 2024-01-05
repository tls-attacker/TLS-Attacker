/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientCertificateTypeExtensionHandler
        extends ExtensionHandler<ClientCertificateTypeExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientCertificateTypeExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(ClientCertificateTypeExtensionMessage message) {
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            if (message.getCertificateTypes().getValue().length != 1) {
                LOGGER.warn("Invalid ClientCertificateType extension. Not adjusting context");
            } else {
                tlsContext.setSelectedClientCertificateType(
                        CertificateType.getCertificateType(
                                message.getCertificateTypes().getValue()[0]));
            }
        } else {
            if (message.getCertificateTypes() != null) {
                tlsContext.setClientCertificateTypeDesiredTypes(
                        CertificateType.getCertificateTypesAsList(
                                message.getCertificateTypes().getValue()));
            } else {
                LOGGER.warn("Null CertificateTypes - not adjusting");
            }
        }
    }
}
