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
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionListParser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateEntryParser extends Parser<CertificateEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public CertificateEntryParser(InputStream stream, TlsContext context) {
        super(stream);
        this.context = context;
    }

    @Override
    public void parse(CertificateEntry entry) {
        LOGGER.debug("Parsing CertificatePair");
        parseCertificateLength(entry);
        parseCertificateBytes(entry);
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            parseExtensionsLength(entry);
            parseExtensionBytes(entry);
        }
        parseX509Certificate(entry);
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            parseExtensions(entry);
        }
    }

    /**
     * Reads the next bytes as the certificateLength of the CertificateEntry and writes them in the
     * message
     */
    private void parseCertificateLength(CertificateEntry pair) {
        pair.setCertificateLength(parseIntField(HandshakeByteLength.CERTIFICATE_LENGTH));
        LOGGER.debug("CertificateLength: " + pair.getCertificateLength().getValue());
    }

    /**
     * Reads the next bytes as the certificate of the CertificateEntry and writes them in the
     * message
     */
    private void parseCertificateBytes(CertificateEntry pair) {
        pair.setCertificateBytes(parseByteArrayField(pair.getCertificateLength().getValue()));
        LOGGER.debug(
                "Certificate: "
                        + ArrayConverter.bytesToHexString(pair.getCertificateBytes().getValue()));
    }

    /**
     * Reads the next bytes as the extensionsLength of the CertificateEntry and writes them in the
     * message
     */
    private void parseExtensionsLength(CertificateEntry pair) {
        pair.setExtensionsLength(parseIntField(HandshakeByteLength.EXTENSION_LENGTH));
        LOGGER.debug("ExtensionsLength: " + pair.getExtensionsLength().getValue());
    }

    /**
     * Reads the next bytes as the extensions of the CertificateEntry and writes them in the message
     */
    private void parseExtensionBytes(CertificateEntry pair) {
        pair.setExtensionBytes(parseByteArrayField(pair.getExtensionsLength().getValue()));
        LOGGER.debug(
                "Extensions: "
                        + ArrayConverter.bytesToHexString(pair.getCertificateBytes().getValue()));
    }

    private void parseExtensions(CertificateEntry pair) {
        ExtensionListParser parser =
                new ExtensionListParser(
                        new ByteArrayInputStream(pair.getExtensionBytes().getValue()),
                        context,
                        false);
        List<ExtensionMessage> extensionMessages = new LinkedList<>();
        parser.parse(extensionMessages);
        pair.setExtensionList(extensionMessages);
    }

    private void parseX509Certificate(CertificateEntry entry) {
        try {
            X509Context x509context = this.context.getTalkingX509Context();
            X509Certificate x509Certificate = new X509Certificate("certificate");
            X509Chooser x509Chooser = x509context.getChooser();
            x509Certificate
                    .getParser(x509Chooser)
                    .parse(new ByteArrayInputStream(entry.getCertificateBytes().getValue()));
            entry.setX509certificate(x509Certificate);
        } catch (Exception E) {
            LOGGER.warn("Could not parse certificate bytes to X509Certificate", E);
        }
    }
}
