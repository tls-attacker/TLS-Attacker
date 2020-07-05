/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateStatusParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusRequestExtensionParser extends ExtensionParser<CertificateStatusRequestExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusRequestExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(CertificateStatusRequestExtensionMessage msg) {
        if (msg.getExtensionLength().getValue() > 0) {
            try {
                LOGGER.debug("Trying to parse Certificate Status Request as regular extension.");
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
            } catch (ParserException e) {
                LOGGER.debug("Certificate Status Request extension parsing failed. Trying to parse as TLS 1.3 CertificateEntry extension.");
                parseAsCertificateStatus(msg);
            }

            if (getBytesLeft() > 0) {
                LOGGER.debug("Certificate Status Request extension parsing left some bytes over. Trying to parse as TLS 1.3 CertificateEntry extension.");
                parseAsCertificateStatus(msg);
            }
        }

    }

    private void parseAsCertificateStatus(CertificateStatusRequestExtensionMessage msg) {
        CertificateStatusMessage certificateStatusMessage = new CertificateStatusMessage();
        CertificateStatusParser certificateStatusParser = new CertificateStatusParser(getStartPoint(), getArray(),
                ProtocolVersion.TLS13);
        certificateStatusParser.parseCertificateEntryContent(certificateStatusMessage);
        msg.setCertificateStatus(certificateStatusMessage);
        LOGGER.debug("Certificate Status Request extension parsed correctly as TLS 1.3 CertificateEntry extension.");
        // Skip ahead the rest of the stuck remaining bytes so we do not
        // parse any remaining bytes as another extension
        parseByteArrayField(getBytesLeft());
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
