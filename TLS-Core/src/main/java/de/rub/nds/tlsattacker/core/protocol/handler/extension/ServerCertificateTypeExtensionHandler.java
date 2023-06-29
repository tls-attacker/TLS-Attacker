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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerCertificateTypeExtensionHandler
        extends ExtensionHandler<ServerCertificateTypeExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerCertificateTypeExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(ServerCertificateTypeExtensionMessage message) {
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            if (message.getCertificateTypes().getValue().length != 1) {
                LOGGER.warn("Invalid ServerCertificateType extension. Not adjusting context");
            } else {
                tlsContext.setSelectedServerCertificateType(
                        CertificateType.getCertificateType(
                                message.getCertificateTypes().getValue()[0]));
            }
        } else {
            tlsContext.setServerCertificateTypeDesiredTypes(
                    CertificateType.getCertificateTypesAsList(
                            message.getCertificateTypes().getValue()));
        }
    }
}
