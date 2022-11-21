/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.protocol.message.certificatestatus.CertificateStatusObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusParser extends HandshakeMessageParser<CertificateStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, HandshakeMessageType.CERTIFICATE_STATUS, version, config);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateStatusMessage msg) {
        LOGGER.debug("Parsing CertificateStatusMessage");
        CertificateStatusGenericParser parser =
            new CertificateStatusGenericParser(0, parseByteArrayField(msg.getLength().getValue()));
        CertificateStatusObject certificateStatus = parser.parse();

        msg.setCertificateStatusType(certificateStatus.getType());
        msg.setOcspResponseLength(certificateStatus.getLength());
        msg.setOcspResponseBytes(certificateStatus.getOcspResponse());
    }

    @Override
    protected CertificateStatusMessage createHandshakeMessage() {
        return new CertificateStatusMessage();
    }
}
