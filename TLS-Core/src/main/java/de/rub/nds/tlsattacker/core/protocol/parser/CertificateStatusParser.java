/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.protocol.message.certificatestatus.CertificateStatusObject;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class CertificateStatusParser extends HandshakeMessageParser<CertificateStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusParser(InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        super(stream, HandshakeMessageType.CERTIFICATE_STATUS, version, tlsContext);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateStatusMessage message) {
        LOGGER.debug("Parsing CertificateStatusMessage");
        CertificateStatusGenericParser parser =
            new CertificateStatusGenericParser(new ByteArrayInputStream(parseByteArrayField(getBytesLeft())));
        CertificateStatusObject certificateStatusObject = new CertificateStatusObject();
        parser.parse(certificateStatusObject);

        message.setCertificateStatusType(certificateStatusObject.getType());
        message.setOcspResponseLength(certificateStatusObject.getLength());
        message.setOcspResponseBytes(certificateStatusObject.getOcspResponse());
    }
}
