/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToHexString;
import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateStatusRequestExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusRequestExtensionHandler extends
        ExtensionHandler<CertificateStatusRequestExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusRequestExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public CertificateStatusRequestExtensionParser getParser(byte[] message, int pointer) {
        return new CertificateStatusRequestExtensionParser(pointer, message);
    }

    @Override
    public CertificateStatusRequestExtensionPreparator getPreparator(CertificateStatusRequestExtensionMessage message) {
        return new CertificateStatusRequestExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public CertificateStatusRequestExtensionSerializer getSerializer(CertificateStatusRequestExtensionMessage message) {
        return new CertificateStatusRequestExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(CertificateStatusRequestExtensionMessage message) {
        context.setCertificateStatusRequestExtensionRequestType(CertificateStatusRequestType
                .getCertificateStatusRequestType(message.getCertificateStatusRequestType().getValue()));
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
