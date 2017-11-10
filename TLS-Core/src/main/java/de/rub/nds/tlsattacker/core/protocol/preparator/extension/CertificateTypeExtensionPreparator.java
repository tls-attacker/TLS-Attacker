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
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class CertificateTypeExtensionPreparator extends ExtensionPreparator<CertificateTypeExtensionMessage> {

    private final CertificateTypeExtensionMessage msg;

    public CertificateTypeExtensionPreparator(Chooser chooser, CertificateTypeExtensionMessage message,
            ExtensionSerializer<CertificateTypeExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setCertificateTypes(CertificateType.toByteArray(chooser.getConfig().getCertificateTypeDesiredTypes()));
        msg.setCertificateTypesLength(msg.getCertificateTypes().getValue().length);
        msg.setIsClientMessage(chooser.getConfig().isCertificateTypeExtensionMessageState());
    }

}
