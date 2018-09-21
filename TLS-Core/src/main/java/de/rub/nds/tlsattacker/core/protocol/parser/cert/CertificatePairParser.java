/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.cert;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificatePairParser extends Parser<CertificatePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificatePairParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public CertificatePair parse() {
        LOGGER.debug("Parsing CertificatePair");
        CertificatePair pair = new CertificatePair();
        parseCertificateLength(pair);
        parseCertificate(pair);
        parseExtensionsLength(pair);
        parseExtensions(pair);
        return pair;
    }

    /**
     * Reads the next bytes as the certificateLength of the CertificatePair and
     * writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCertificateLength(CertificatePair pair) {
        pair.setCertificateLength(parseIntField(HandshakeByteLength.CERTIFICATE_LENGTH));
        LOGGER.debug("CertificateLength: " + pair.getCertificateLength().getValue());
    }

    /**
     * Reads the next bytes as the certificate of the CertificatePair and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCertificate(CertificatePair pair) {
        pair.setCertificate(parseByteArrayField(pair.getCertificateLength().getValue()));
        LOGGER.debug("Certificate: " + ArrayConverter.bytesToHexString(pair.getCertificate().getValue()));
    }

    /**
     * Reads the next bytes as the extensionsLength of the CertificatePair and
     * writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseExtensionsLength(CertificatePair pair) {
        pair.setExtensionsLength(parseIntField(HandshakeByteLength.EXTENSION_LENGTH));
        LOGGER.debug("ExtensionsLength: " + pair.getCertificateLength().getValue());
    }

    /**
     * Reads the next bytes as the extensions of the CertificatePair and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseExtensions(CertificatePair pair) {
        pair.setExtensions(parseByteArrayField(pair.getExtensionsLength().getValue()));
        LOGGER.debug("Extensions: " + ArrayConverter.bytesToHexString(pair.getCertificate().getValue()));
    }

}
