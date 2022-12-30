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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CertificatePairParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParserFactory;
import java.io.ByteArrayInputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateMessageParser extends HandshakeMessageParser<CertificateMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param startposition Position in the array where the
     * HandshakeMessageParser is supposed to start parsing
     * @param array The byte[] which the HandshakeMessageParser is supposed to
     * parse
     * @param version Version of the Protocol
     * @param config A Config used in the current context
     */
    public CertificateMessageParser(int startposition, byte[] array, ProtocolVersion version, Config config) {
        super(startposition, array, HandshakeMessageType.CERTIFICATE, version, config);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateMessage msg) {
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

    @Override
    protected CertificateMessage createHandshakeMessage() {
        return new CertificateMessage();
    }

    /**
     * Reads the next bytes as the RequestContextLength and writes them in the
     * message
     *
     * @param msg Message to write in
     */
    private void parseRequestContextLength(CertificateMessage msg) {
        msg.setRequestContextLength(parseIntField(HandshakeByteLength.CERTIFICATE_REQUEST_CONTEXT_LENGTH));
        LOGGER.debug("RequestContextLength: " + msg.getRequestContextLength());
    }

    /**
     * Reads the next bytes as the requestContextBytes and writes them in the
     * message
     *
     * @param msg Message to write in
     */
    private void parseRequestContextBytes(CertificateMessage msg) {
        msg.setRequestContext(parseByteArrayField(msg.getRequestContextLength().getValue()));
        LOGGER.debug("RequestContextBytes: " + ArrayConverter.bytesToHexString(msg.getRequestContext()));
    }

    /**
     * Reads the next bytes as the CertificateLength and writes them in the
     * message
     *
     * @param msg Message to write in
     */
    private void parseCertificatesListLength(CertificateMessage msg) {
        msg.setCertificatesListLength(parseIntField(HandshakeByteLength.CERTIFICATES_LENGTH));
        LOGGER.debug("CertificatesListLength: " + msg.getCertificatesListLength());
    }

    /**
     * Reads the next bytes as the CertificateBytes and writes them in the
     * message
     *
     * @param msg Message to write in
     */
    private void parseCertificateListBytes(CertificateMessage msg) {
        msg.setCertificatesListBytes(parseByteArrayField(msg.getCertificatesListLength().getValue()));
        LOGGER.debug("CertificatesListBytes: " + ArrayConverter.bytesToHexString(msg.getCertificatesListBytes()));
    }

    /**
     * Reads the bytes from the CertificateListBytes and writes them in the
     * CertificateList
     *
     * @param msg Message to write in
     */
    private void parseCertificateList(CertificateMessage msg) {
        ByteArrayInputStream stream = new ByteArrayInputStream(msg.getCertificatesListBytes().getValue());
        List<CertificatePair> pairList = new LinkedList<>();
        while (stream.available() > 0) {
            CertificatePairParser parser = new CertificatePairParser(stream);
            pairList.add(parser.parse());
        }
        msg.setCertificatesList(pairList);
    }
}
