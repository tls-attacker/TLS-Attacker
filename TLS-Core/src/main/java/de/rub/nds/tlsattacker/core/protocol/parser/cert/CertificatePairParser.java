/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.cert;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificatePairParser extends Parser<CertificatePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificatePairParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(CertificatePair pair) {
        LOGGER.debug("Parsing CertificatePair");
        parseCertificateLength(pair);
        parseCertificate(pair);
        parseExtensionsLength(pair);
        parseExtensions(pair);
    }

    /**
     * Reads the next bytes as the certificateLength of the CertificatePair and writes them in the
     * message
     */
    private void parseCertificateLength(CertificatePair pair) {
        pair.setCertificateLength(parseIntField(HandshakeByteLength.CERTIFICATE_LENGTH));
        LOGGER.debug("CertificateLength: " + pair.getCertificateLength().getValue());
    }

    /**
     * Reads the next bytes as the certificate of the CertificatePair and writes them in the message
     */
    private void parseCertificate(CertificatePair pair) {
        pair.setCertificate(parseByteArrayField(pair.getCertificateLength().getValue()));
        LOGGER.debug("Certificate: {}", pair.getCertificate().getValue());
    }

    /**
     * Reads the next bytes as the extensionsLength of the CertificatePair and writes them in the
     * message
     */
    private void parseExtensionsLength(CertificatePair pair) {
        pair.setExtensionsLength(parseIntField(HandshakeByteLength.EXTENSION_LENGTH));
        LOGGER.debug("ExtensionsLength: " + pair.getCertificateLength().getValue());
    }

    /**
     * Reads the next bytes as the extensions of the CertificatePair and writes them in the message
     */
    private void parseExtensions(CertificatePair pair) {
        pair.setExtensions(parseByteArrayField(pair.getExtensionsLength().getValue()));
        LOGGER.debug("Extensions: {}", pair.getCertificate().getValue());
    }
}
