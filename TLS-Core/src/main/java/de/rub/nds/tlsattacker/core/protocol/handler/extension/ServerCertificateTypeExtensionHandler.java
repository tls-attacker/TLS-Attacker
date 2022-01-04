/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerCertificateTypeExtensionHandler extends ExtensionHandler<ServerCertificateTypeExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerCertificateTypeExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(ServerCertificateTypeExtensionMessage message) {
        if (context.getTalkingConnectionEndType() == ConnectionEndType.SERVER) {
            if (message.getCertificateTypes().getValue().length != 1) {
                LOGGER.warn("Invalid ServerCertificateType extension. Not adjusting context");
            } else {
                context.setSelectedServerCertificateType(
                        CertificateType.getCertificateType(message.getCertificateTypes().getValue()[0]));
            }
        } else {
            context.setServerCertificateTypeDesiredTypes(
                    CertificateType.getCertificateTypesAsList(message.getCertificateTypes().getValue()));
        }
    }

}
