/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.cert;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificatePairSerializer extends Serializer<CertificateEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificateEntry pair;
    private final ProtocolVersion version;

    public CertificatePairSerializer(CertificateEntry pair, ProtocolVersion version) {
        this.pair = pair;
        this.version = version;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing CertificatePair");
        writeCertificateLength(pair);
        writeCertificate(pair);
        if (version.isTLS13()) {
            writeExtensionsLength(pair);
            if (pair.getExtensionBytes() != null && pair.getExtensionBytes().getValue() != null) {
                writeExtensions(pair);
            }
        }
        return getAlreadySerialized();
    }

    private void writeCertificateLength(CertificateEntry pair) {
        appendInt(pair.getCertificateLength().getValue(), HandshakeByteLength.CERTIFICATE_LENGTH);
        LOGGER.debug("CertificateLength: " + pair.getCertificateLength().getValue());
    }

    private void writeCertificate(CertificateEntry pair) {
        appendBytes(pair.getCertificateBytes().getValue());
        LOGGER.debug(
                "Certificate: "
                        + ArrayConverter.bytesToHexString(pair.getCertificateBytes().getValue()));
    }

    private void writeExtensionsLength(CertificateEntry pair) {
        appendInt(pair.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
        LOGGER.debug("ExtensionsLength: " + pair.getExtensionsLength().getValue());
    }

    private void writeExtensions(CertificateEntry pair) {
        appendBytes(pair.getExtensionBytes().getValue());
        LOGGER.debug(
                "Extensions: "
                        + ArrayConverter.bytesToHexString(pair.getExtensionBytes().getValue()));
    }
}
