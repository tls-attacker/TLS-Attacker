/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.cert;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificatePairSerializer extends Serializer<CertificatePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CertificatePair pair;
    private final ProtocolVersion version;

    public CertificatePairSerializer(CertificatePair pair, ProtocolVersion version) {
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
            if (pair.getExtensions() != null && pair.getExtensions().getValue() != null) {
                writeExtensions(pair);
            }
        }
        return getAlreadySerialized();
    }

    private void writeCertificateLength(CertificatePair pair) {
        appendInt(pair.getCertificateLength().getValue(), HandshakeByteLength.CERTIFICATE_LENGTH);
        LOGGER.debug("CertificateLength: " + pair.getCertificateLength().getValue());
    }

    private void writeCertificate(CertificatePair pair) {
        appendBytes(pair.getCertificate().getValue());
        LOGGER.debug("Certificate: {}", pair.getCertificate().getValue());
    }

    private void writeExtensionsLength(CertificatePair pair) {
        appendInt(pair.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
        LOGGER.debug("ExtensionsLength: " + pair.getExtensionsLength().getValue());
    }

    private void writeExtensions(CertificatePair pair) {
        appendBytes(pair.getExtensions().getValue());
        LOGGER.debug("Extensions: {}", pair.getExtensions().getValue());
    }
}
