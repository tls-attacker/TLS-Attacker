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
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ClientCertificateTypeExtensionPreparator extends
        ExtensionPreparator<ClientCertificateTypeExtensionMessage> {

    private final ClientCertificateTypeExtensionMessage msg;

    public ClientCertificateTypeExtensionPreparator(Chooser chooser, ClientCertificateTypeExtensionMessage message,
            ExtensionSerializer<ClientCertificateTypeExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setCertificateTypes(CertificateType.toByteArray(chooser.getConfig().getClientCertificateTypeDesiredTypes()));
        msg.setCertificateTypesLength(msg.getCertificateTypes().getValue().length);
        msg.setIsClientMessage(chooser.getConfig().isClientCertificateTypeExtensionMessageState());
    }

}
