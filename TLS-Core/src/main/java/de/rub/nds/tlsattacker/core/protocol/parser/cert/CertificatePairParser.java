/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.cert;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionListParser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificatePairParser extends Parser<CertificatePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public CertificatePairParser(InputStream stream, TlsContext context) {
        super(stream);
        this.context = context;
    }

    @Override
    public void parse(CertificatePair pair) {
        LOGGER.debug("Parsing CertificatePair");
        parseCertificateLength(pair);
        parseCertificate(pair);
        parseExtensionsLength(pair);
        parseExtensionBytes(pair);
        parseExtensions(pair);
    }

    /**
     * Reads the next bytes as the certificateLength of the CertificatePair and
     * writes them in the message
     */
    private void parseCertificateLength(CertificatePair pair) {
        pair.setCertificateLength(parseIntField(HandshakeByteLength.CERTIFICATE_LENGTH));
        LOGGER.debug("CertificateLength: " + pair.getCertificateLength().getValue());
    }

    /**
     * Reads the next bytes as the certificate of the CertificatePair and writes
     * them in the message
     */
    private void parseCertificate(CertificatePair pair) {
        pair.setCertificateBytes(parseByteArrayField(pair.getCertificateLength().getValue()));
        LOGGER.debug(
                "Certificate: "
                + ArrayConverter.bytesToHexString(pair.getCertificateBytes().getValue()));
    }

    /**
     * Reads the next bytes as the extensionsLength of the CertificatePair and
     * writes them in the message
     */
    private void parseExtensionsLength(CertificatePair pair) {
        pair.setExtensionsLength(parseIntField(HandshakeByteLength.EXTENSION_LENGTH));
        LOGGER.debug("ExtensionsLength: " + pair.getExtensionsLength().getValue());
    }

    /**
     * Reads the next bytes as the extensions of the CertificatePair and writes
     * them in the message
     */
    private void parseExtensionBytes(CertificatePair pair) {
        pair.setExtensionBytes(parseByteArrayField(pair.getExtensionsLength().getValue()));
        LOGGER.debug(
                "Extensions: "
                + ArrayConverter.bytesToHexString(pair.getCertificateBytes().getValue()));
    }

    private void parseExtensions(CertificatePair pair) {
        ExtensionListParser parser
                = new ExtensionListParser(new ByteArrayInputStream(pair.getCertificateBytes().getValue()), context, false);
        List<ExtensionMessage> extensionMessages = new LinkedList<>();
        parser.parse(extensionMessages);
        pair.setExtensionList(extensionMessages);
    }
}
