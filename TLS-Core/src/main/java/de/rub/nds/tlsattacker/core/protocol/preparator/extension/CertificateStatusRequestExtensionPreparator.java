/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusRequestExtensionPreparator extends
        ExtensionPreparator<CertificateStatusRequestExtensionMessage> {
    private final CertificateStatusRequestExtensionMessage msg;

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusRequestExtensionPreparator(Chooser chooser,
            CertificateStatusRequestExtensionMessage message,
            ExtensionSerializer<CertificateStatusRequestExtensionMessage> serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setCertificateStatusRequestType(chooser.getConfig().getCertificateStatusRequestExtensionRequestType()
                .getCertificateStatusRequestValue());
        LOGGER.debug("Prepared the CertificateStatusRequestExtension with request type "
                + CertificateStatusRequestType.getCertificateStatusRequestType(msg.getCertificateStatusRequestType()
                        .getValue()));
        msg.setResponderIDList(chooser.getConfig().getCertificateStatusRequestExtensionResponderIDList());
        msg.setResponderIDListLength(msg.getResponderIDList().getValue().length);
        LOGGER.debug("Prepared the CertificateStatusRequestExtension with responder ID list "
                + bytesToHexString(msg.getResponderIDList()));
        msg.setRequestExtension(chooser.getConfig().getCertificateStatusRequestExtensionRequestExtension());
        msg.setRequestExtensionLength(msg.getRequestExtension().getValue().length);
        LOGGER.debug("Prepared the CertificateStatusRequestExtension with request extension "
                + bytesToHexString(msg.getRequestExtension()));
    }

}
