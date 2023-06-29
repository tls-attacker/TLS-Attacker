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
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CertificatePairParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionListParser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateMessageParser extends HandshakeMessageParser<CertificateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private TlsContext tlsContext;

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param tlsContext
     */
    public CertificateMessageParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext.getChooser().getSelectedProtocolVersion(), tlsContext);
        this.tlsContext = tlsContext;
    }

    @Override
    public void parse(CertificateMessage msg) {
        LOGGER.debug("Parsing CertificateMessage");
        if (getVersion().isTLS13()) {
            parseRequestContextLength(msg);
            parseRequestContextBytes(msg);
        }
        parseCertificatesListLength(msg);
        parseCertificateListBytes(msg);
        if (getVersion().isTLS13()) {
            parseCertificateList(msg);
        }
    }

    /**
     * Reads the next bytes as the RequestContextLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseRequestContextLength(CertificateMessage msg) {
        msg.setRequestContextLength(
                parseIntField(HandshakeByteLength.CERTIFICATE_REQUEST_CONTEXT_LENGTH));
        LOGGER.debug("RequestContextLength: " + msg.getRequestContextLength());
    }

    /**
     * Reads the next bytes as the requestContextBytes and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseRequestContextBytes(CertificateMessage msg) {
        msg.setRequestContext(parseByteArrayField(msg.getRequestContextLength().getValue()));
        LOGGER.debug("RequestContextBytes: {}", msg.getRequestContext());
    }

    /**
     * Reads the next bytes as the CertificateLength and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseCertificatesListLength(CertificateMessage msg) {
        msg.setCertificatesListLength(parseIntField(HandshakeByteLength.CERTIFICATES_LENGTH));
        LOGGER.debug("CertificatesListLength: " + msg.getCertificatesListLength());
    }

    /**
     * Reads the next bytes as the CertificateBytes and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseCertificateListBytes(CertificateMessage msg) {
        msg.setCertificatesListBytes(
                parseByteArrayField(msg.getCertificatesListLength().getValue()));
        LOGGER.debug("CertificatesListBytes: {}", msg.getCertificatesListBytes());
    }

    /**
     * Reads the bytes from the CertificateListBytes and writes them in the CertificateList
     *
     * @param msg Message to write in
     */
    private void parseCertificateList(CertificateMessage msg) {
        List<CertificatePair> pairList = new LinkedList<>();
        ByteArrayInputStream innerStream =
                new ByteArrayInputStream(msg.getCertificatesListBytes().getValue());
        while (innerStream.available() > 0) {
            CertificatePair pair = new CertificatePair();
            CertificatePairParser parser = new CertificatePairParser(innerStream);
            parser.parse(pair);
            pairList.add(pair);
        }
        msg.setCertificatesList(pairList);

        List<CertificateEntry> entryList = new LinkedList<>();
        for (CertificatePair pair : msg.getCertificatesList()) {
            ExtensionListParser parser =
                    new ExtensionListParser(
                            new ByteArrayInputStream(pair.getExtensions().getValue()),
                            tlsContext,
                            false);
            List<ExtensionMessage> extensionMessages = new LinkedList<>();
            parser.parse(extensionMessages);
            entryList.add(
                    new CertificateEntry(pair.getCertificate().getValue(), extensionMessages));
        }
        msg.setCertificatesListAsEntry(entryList);
    }
}
