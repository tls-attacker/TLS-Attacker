/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusSerializer extends HandshakeMessageSerializer<CertificateStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificateStatusMessage msg;

    public CertificateStatusSerializer(CertificateStatusMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing CertificateStatusMessage");
        writeCertificateStatusType(msg);
        writeOcspResponseLength(msg);
        writeOcspResponse(msg);
        return getAlreadySerialized();
    }

    private void writeCertificateStatusType(CertificateStatusMessage msg) {
        appendInt(msg.getCertificateStatusType().getValue(), HandshakeByteLength.CERTIFICATE_STATUS_TYPE_LENGTH);
        LOGGER.debug("CertificateStatusType: " + msg.getCertificateStatusType().getValue());
    }

    private void writeOcspResponseLength(CertificateStatusMessage msg) {
        appendInt(msg.getOcspResponseLength().getValue(), HandshakeByteLength.CERTIFICATE_STATUS_RESPONSE_LENGTH);
        LOGGER.debug("OCSP Response Length: " + msg.getOcspResponseLength().getValue());
    }

    private void writeOcspResponse(CertificateStatusMessage msg) {
        appendBytes(msg.getOcspResponseBytes().getValue());
        LOGGER.debug("OCSP Response: " + ArrayConverter.bytesToHexString(msg.getOcspResponseBytes().getValue()));
    }
}
