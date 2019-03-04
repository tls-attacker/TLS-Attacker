/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusRequestExtensionParser extends ExtensionParser<CertificateStatusRequestExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusRequestExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(CertificateStatusRequestExtensionMessage msg) {
        msg.setCertificateStatusRequestType(parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_STATUS_TYPE));
        LOGGER.debug("Parsed the status type " + msg.getCertificateStatusRequestType().getValue());
        msg.setResponderIDListLength(parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_RESPONDER_ID_LIST_LENGTH));
        msg.setResponderIDList(parseByteArrayField(msg.getResponderIDListLength().getValue()));
        LOGGER.debug("Parsed the responder ID list with length " + msg.getResponderIDListLength().getValue()
                + " and value " + ArrayConverter.bytesToHexString(msg.getResponderIDList()));
        msg.setRequestExtensionLength(parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_REQUEST_EXTENSION_LENGTH));
        msg.setRequestExtension(parseByteArrayField(msg.getRequestExtensionLength().getValue()));
        LOGGER.debug("Parsed the request extension with length " + msg.getRequestExtensionLength().getValue()
                + " and value " + ArrayConverter.bytesToHexString(msg.getRequestExtension()));

    }

    @Override
    protected CertificateStatusRequestExtensionMessage createExtensionMessage() {
        return new CertificateStatusRequestExtensionMessage();
    }

}
