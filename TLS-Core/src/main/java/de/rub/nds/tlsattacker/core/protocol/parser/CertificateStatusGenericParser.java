/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.certificatestatus.CertificateStatusObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusGenericParser extends Parser {

    private static final Logger LOGGER = LogManager.getLogger();

    private CertificateStatusObject certificateStatusObject = new CertificateStatusObject();

    public CertificateStatusGenericParser(int pointer, byte[] array) {
        super(pointer, array);
    }

    @Override
    public CertificateStatusObject parse() {
        LOGGER.debug("Parsing CertificateStatus with generic parser.");

        int type = parseIntField(HandshakeByteLength.CERTIFICATE_STATUS_TYPE_LENGTH);
        certificateStatusObject.setType(type);
        LOGGER.debug("CertificateStatusType: " + type);

        int length = parseIntField(HandshakeByteLength.CERTIFICATE_STATUS_RESPONSE_LENGTH);
        certificateStatusObject.setLength(length);
        LOGGER.debug("OCSP Response Length: " + length);

        byte[] ocspResponse = parseByteArrayField(length);
        certificateStatusObject.setOcspResponse(ocspResponse);
        LOGGER.debug("OCSP Response: " + ArrayConverter.bytesToHexString(ocspResponse));

        return certificateStatusObject;
    }
}