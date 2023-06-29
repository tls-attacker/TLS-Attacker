/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.certificatestatus.CertificateStatusObject;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateStatusGenericParser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusRequestExtensionParser
        extends ExtensionParser<CertificateStatusRequestExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ProtocolVersion selectedVersion;

    public CertificateStatusRequestExtensionParser(
            InputStream stream, ProtocolVersion selectedVersion, TlsContext tlsContext) {
        super(stream, tlsContext);
        this.selectedVersion = selectedVersion;
    }

    @Override
    public void parse(CertificateStatusRequestExtensionMessage msg) {
        if (!selectedVersion.isTLS13()) {
            msg.setCertificateStatusRequestType(
                    parseIntField(ExtensionByteLength.CERTIFICATE_STATUS_REQUEST_STATUS_TYPE));
            LOGGER.debug(
                    "Parsed the status type " + msg.getCertificateStatusRequestType().getValue());
            msg.setResponderIDListLength(
                    parseIntField(
                            ExtensionByteLength
                                    .CERTIFICATE_STATUS_REQUEST_RESPONDER_ID_LIST_LENGTH));
            msg.setResponderIDList(parseByteArrayField(msg.getResponderIDListLength().getValue()));
            LOGGER.debug(
                    "Parsed the responder ID list with length {} and value {}",
                    msg.getResponderIDListLength().getValue(),
                    msg.getResponderIDList());
            msg.setRequestExtensionLength(
                    parseIntField(
                            ExtensionByteLength
                                    .CERTIFICATE_STATUS_REQUEST_REQUEST_EXTENSION_LENGTH));
            msg.setRequestExtension(
                    parseByteArrayField(msg.getRequestExtensionLength().getValue()));
            LOGGER.debug(
                    "Parsed the request extension with length {} and value {}",
                    msg.getRequestExtensionLength().getValue(),
                    msg.getRequestExtension());
        } else {
            parseAsCertificateStatus(msg);
        }
    }

    private void parseAsCertificateStatus(CertificateStatusRequestExtensionMessage msg) {
        CertificateStatusGenericParser certificateStatusGenericParser =
                new CertificateStatusGenericParser(
                        new ByteArrayInputStream(
                                parseByteArrayField(msg.getExtensionLength().getValue())));
        CertificateStatusObject certificateStatus = new CertificateStatusObject();
        certificateStatusGenericParser.parse(certificateStatus);
        msg.setCertificateStatusType(certificateStatus.getType());
        msg.setOcspResponseLength(certificateStatus.getLength());
        msg.setOcspResponseBytes(certificateStatus.getOcspResponse());
    }
}
