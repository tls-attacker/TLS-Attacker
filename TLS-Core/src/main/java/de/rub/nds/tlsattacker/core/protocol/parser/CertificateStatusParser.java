/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateStatusParser extends HandshakeMessageParser<CertificateStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateStatusParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.CERTIFICATE_STATUS, version);
    }

    public void parseCertificateEntryContent(CertificateStatusMessage msg) {
        LOGGER.debug("Parsing status_request CertificateEntry extension as CertificateStatusMessage");
        // Skip ahead type & length, as they're from the extension and we don't
        // care about them
        setPointer(getPointer() + HandshakeByteLength.MESSAGE_TYPE + HandshakeByteLength.MESSAGE_LENGTH_FIELD);
        parseCertificateStatusType(msg);
        parseOcspResponseLength(msg);
        parseOcspResponse(msg);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateStatusMessage msg) {
        LOGGER.debug("Parsing CertificateStatusMessage");
        parseCertificateStatusType(msg);
        parseOcspResponseLength(msg);
        parseOcspResponse(msg);
    }

    @Override
    protected CertificateStatusMessage createHandshakeMessage() {
        return new CertificateStatusMessage();
    }

    private void parseCertificateStatusType(CertificateStatusMessage msg) {
        msg.setCertificateStatusType(parseIntField(HandshakeByteLength.CERTIFICATE_STATUS_TYPE_LENGTH));
        LOGGER.debug("CertificateStatusType: " + msg.getCertificateStatusType().getValue());
    }

    private void parseOcspResponseLength(CertificateStatusMessage msg) {
        msg.setOcspResponseLength(parseIntField(HandshakeByteLength.CERTIFICATE_STATUS_RESPONSE_LENGTH));
        LOGGER.debug("OCSP Response Length: " + msg.getOcspResponseLength().getValue());
    }

    private void parseOcspResponse(CertificateStatusMessage msg) {
        msg.setOcspResponseBytes(parseByteArrayField(msg.getOcspResponseLength().getValue()));
        LOGGER.debug("OCSP Response: " + ArrayConverter.bytesToHexString(msg.getOcspResponseBytes().getValue()));
    }
}
