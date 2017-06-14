/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateStatusRequestExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class CertificateStatusRequestExtensionHandler extends
        ExtensionHandler<CertificateStatusRequestExtensionMessage> {

    public CertificateStatusRequestExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public CertificateStatusRequestExtensionParser getParser(byte[] message, int pointer) {
        return new CertificateStatusRequestExtensionParser(pointer, message);
    }

    @Override
    public CertificateStatusRequestExtensionPreparator getPreparator(CertificateStatusRequestExtensionMessage message) {
        return new CertificateStatusRequestExtensionPreparator(context, message);
    }

    @Override
    public CertificateStatusRequestExtensionSerializer getSerializer(CertificateStatusRequestExtensionMessage message) {
        return new CertificateStatusRequestExtensionSerializer(message);
    }

    @Override
    public void adjustTLSContext(CertificateStatusRequestExtensionMessage message) {
        context.setCertificateStatusRequestExtensionRequestType(message.getCertificateStatusRequestType().getValue());
        LOGGER.debug("Adjusted the Certificate Status Request Type in the TLSContext to "
                + context.getCertificateStatusRequestExtensionRequestType());
        context.setCertificateStatusRequestExtensionRequestExtension(message.getRequestExtension().getValue());
        LOGGER.debug("Adjusted the Certificate Status Request Request Extension to "
                + bytesToHexString(context.getCertificateStatusRequestExtensionRequestExtension()));
        context.setCertificateStatusRequestExtensionResponderIDList(message.getResponderIDList().getValue());
        LOGGER.debug("Adjusted the Certificate Status Request Responder ID List to "
                + bytesToHexString(context.getCertificateStatusRequestExtensionResponderIDList()));
    }

}
