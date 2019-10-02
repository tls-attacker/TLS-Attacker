/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RequestItemV2Serializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class CertificateStatusRequestV2ExtensionPreparator extends
        ExtensionPreparator<CertificateStatusRequestV2ExtensionMessage> {

    private final CertificateStatusRequestV2ExtensionMessage msg;

    public CertificateStatusRequestV2ExtensionPreparator(Chooser chooser,
            CertificateStatusRequestV2ExtensionMessage message,
            ExtensionSerializer<CertificateStatusRequestV2ExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setStatusRequestList(chooser.getConfig().getStatusRequestV2RequestList());
        int listLength = 0;
        byte[] itemAsBytes;

        for (RequestItemV2 item : msg.getStatusRequestList()) {
            RequestItemV2Preparator preparator = new RequestItemV2Preparator(chooser, item);
            preparator.prepare();
            RequestItemV2Serializer serializer = new RequestItemV2Serializer(item);
            itemAsBytes = serializer.serialize();
            listLength += itemAsBytes.length;
        }

        msg.setStatusRequestListLength(listLength);
    }

}
