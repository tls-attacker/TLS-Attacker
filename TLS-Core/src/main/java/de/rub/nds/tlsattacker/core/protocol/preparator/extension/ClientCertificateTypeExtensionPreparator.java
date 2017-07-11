/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class ClientCertificateTypeExtensionPreparator extends
        ExtensionPreparator<ClientCertificateTypeExtensionMessage> {

    private final ClientCertificateTypeExtensionMessage msg;

    public ClientCertificateTypeExtensionPreparator(TlsContext context, ClientCertificateTypeExtensionMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setCertificateTypes(CertificateType.toByteArray(context.getConfig().getClientCertificateTypeDesiredTypes()));
        msg.setCertificateTypesLength(msg.getCertificateTypes().getValue().length);
        msg.setIsClientMessage(context.getConfig().isClientCertificateTypeExtensionMessageState());
    }

}
