/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.certificatestatus.CertificateStatusObject;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusGenericParser extends Parser<CertificateStatusObject> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusGenericParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(CertificateStatusObject certificateStatusObject) {
        LOGGER.debug("Parsing CertificateStatus with generic parser.");

        int type = parseIntField(HandshakeByteLength.CERTIFICATE_STATUS_TYPE_LENGTH);
        certificateStatusObject.setType(type);
        LOGGER.debug("CertificateStatusType: " + type);

        int length = parseIntField(HandshakeByteLength.CERTIFICATE_STATUS_RESPONSE_LENGTH);
        certificateStatusObject.setLength(length);
        LOGGER.debug("OCSP Response Length: " + length);

        byte[] ocspResponse = parseByteArrayField(length);
        certificateStatusObject.setOcspResponse(ocspResponse);
        LOGGER.debug("OCSP Response: {}", ocspResponse);
    }
}
