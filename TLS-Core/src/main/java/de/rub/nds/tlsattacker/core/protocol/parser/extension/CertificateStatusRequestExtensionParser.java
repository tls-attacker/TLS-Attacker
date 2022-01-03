/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.certificatestatus.CertificateStatusObject;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateStatusGenericParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusRequestExtensionParser extends ExtensionParser<CertificateStatusRequestExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private int startOfContentPointer;

    public CertificateStatusRequestExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(CertificateStatusRequestExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 0) {
            // Save pointer in case we need to jump to TLS 1.3 & reset the
            // parser
            startOfContentPointer = getPointer();
            try {
                LOGGER.debug("Trying to parse Certificate Status Request as regular extension.");
                msg.setCertificateStatusRequestType(
                    parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_STATUS_TYPE));
                LOGGER.debug("Parsed the status type " + msg.getCertificateStatusRequestType().getValue());
                msg.setResponderIDListLength(
                    parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_RESPONDER_ID_LIST_LENGTH));
                msg.setResponderIDList(parseByteArrayField(msg.getResponderIDListLength().getValue()));
                LOGGER.debug("Parsed the responder ID list with length " + msg.getResponderIDListLength().getValue()
                    + " and value " + ArrayConverter.bytesToHexString(msg.getResponderIDList()));
                msg.setRequestExtensionLength(
                    parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_REQUEST_EXTENSION_LENGTH));
                msg.setRequestExtension(parseByteArrayField(msg.getRequestExtensionLength().getValue()));
                LOGGER.debug("Parsed the request extension with length " + msg.getRequestExtensionLength().getValue()
                    + " and value " + ArrayConverter.bytesToHexString(msg.getRequestExtension()));
            } catch (ParserException e) {
                LOGGER.debug(
                    "Certificate Status Request extension parsing failed. Trying to parse as TLS 1.3 CertificateEntry"
                        + " extension.");
                parseAsCertificateStatus(msg);
            }

            // Alternative check for getBytesLeft(), as getBytesLeft() would be
            // greater than 0 if there is another extension. If value is below
            // 0, it means that we parsed too little, and therefore likely is a
            // TLS 1.3 extension.
            if ((getPointer() - startOfContentPointer - msg.getExtensionLength().getValue()) < 0) {
                LOGGER.debug(
                    "Certificate Status Request extension parsing left some bytes over. Trying to parse as TLS 1.3 "
                        + "CertificateEntry extension.");
                parseAsCertificateStatus(msg);
            }
        }

    }

    private void parseAsCertificateStatus(CertificateStatusRequestExtensionMessage msg) {
        // Reset parser and start again for TLS 1.3 extension
        setPointer(startOfContentPointer);
        CertificateStatusGenericParser certificateStatusGenericParser =
            new CertificateStatusGenericParser(0, parseByteArrayField(msg.getExtensionLength().getValue()));
        CertificateStatusObject certificateStatus = certificateStatusGenericParser.parse();

        // Set TLS 1.3 fields
        msg.setCertificateStatusType(certificateStatus.getType());
        msg.setOcspResponseLength(certificateStatus.getLength());
        msg.setOcspResponseBytes(certificateStatus.getOcspResponse());

        // And clean up fields from aborted parsing
        msg.setResponderIDListLength(null);
        msg.setRequestExtensionLength(null);
        msg.setResponderIDList((ModifiableByteArray) null);
        msg.setRequestExtension((ModifiableByteArray) null);
    }

    @Override
    protected CertificateStatusRequestExtensionMessage createExtensionMessage() {
        return new CertificateStatusRequestExtensionMessage();
    }

}
