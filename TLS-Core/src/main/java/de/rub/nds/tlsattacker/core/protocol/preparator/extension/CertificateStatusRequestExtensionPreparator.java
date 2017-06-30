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
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CertificateStatusRequestExtensionPreparator extends
        ExtensionPreparator<CertificateStatusRequestExtensionMessage> {
    private final CertificateStatusRequestExtensionMessage msg;

    public CertificateStatusRequestExtensionPreparator(TlsContext context,
            CertificateStatusRequestExtensionMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        msg.setCertificateStatusRequestType(context.getConfig().getCertificateStatusRequestExtensionRequestType()
                .getCertificateStatusRequestValue());
        LOGGER.debug("Prepared the CertificateStatusRequestExtension with request type "
                + CertificateStatusRequestType.getCertificateStatusRequestType(msg.getCertificateStatusRequestType()
                        .getValue()));
        msg.setResponderIDList(context.getConfig().getCertificateStatusRequestExtensionResponderIDList());
        msg.setResponderIDListLength(msg.getResponderIDList().getValue().length);
        LOGGER.debug("Prepared the CertificateStatusRequestExtension with responder ID list "
                + bytesToHexString(msg.getResponderIDList()));
        msg.setRequestExtension(context.getConfig().getCertificateStatusRequestExtensionRequestExtension());
        msg.setRequestExtensionLength(msg.getRequestExtension().getValue().length);
        LOGGER.debug("Prepared the CertificateStatusRequestExtension with request extension "
                + bytesToHexString(msg.getRequestExtension()));
    }

}
