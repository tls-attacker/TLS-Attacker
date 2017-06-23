/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParserFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class CertificateMessageParser extends HandshakeMessageParser<CertificateMessage> {

    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *            Position in the array where the HandshakeMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the HandshakeMessageParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public CertificateMessageParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, HandshakeMessageType.CERTIFICATE, version);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateMessage msg) {
        if (getVersion() == ProtocolVersion.TLS13) {
            parseRequestContextLength(msg);
            parseRequestContextBytes(msg);
        }
        parseCertificatesListLength(msg);
        parseCertificateListBytes(msg);
        if (getVersion() == ProtocolVersion.TLS13) {
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
     * @param msg
     *            Message to write in
     */
    private void parseRequestContextLength(CertificateMessage msg) {
        msg.setRequestContextLength(parseIntField(HandshakeByteLength.CERTIFICATE_REQUEST_CONTEXT_LENGTH));
        LOGGER.debug("RequestContextLength: " + msg.getRequestContextLength());
    }

    /**
     * Reads the next bytes as the requestContextBytes and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseRequestContextBytes(CertificateMessage msg) {
        msg.setRequestContext(parseByteArrayField(msg.getRequestContextLength().getValue()));
        LOGGER.debug("RequestContextBytes: " + ArrayConverter.bytesToHexString(msg.getRequestContext()));
    }

    /**
     * Reads the next bytes as the CertificateLength and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCertificatesListLength(CertificateMessage msg) {
        msg.setCertificatesListLength(parseIntField(HandshakeByteLength.CERTIFICATES_LENGTH));
        LOGGER.debug("CertificatesListLength: " + msg.getCertificatesListLength());
    }

    /**
     * Reads the next bytes as the CertificateBytes and writes them in the
     * message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCertificateListBytes(CertificateMessage msg) {
        msg.setCertificatesListBytes(parseByteArrayField(msg.getCertificatesListLength().getValue()));
        LOGGER.debug("CertificatesListBytes: " + ArrayConverter.bytesToHexString(msg.getCertificatesListBytes()));
    }

    /**
     * Reads the bytes from the CertificateListBytes and writes them in the
     * CertificateList
     *
     * @param msg
     *            Message to write in
     */
    private void parseCertificateList(CertificateMessage msg) {
        int position = 0;
        List<CertificatePair> pairList = new LinkedList<>();
        while (position < msg.getCertificatesListLength().getValue()) {
            CertificatePairParser parser = new CertificatePairParser(position, msg.getCertificatesListBytes()
                    .getValue());
            pairList.add(parser.parse());
            position = parser.getPointer();
        }
        msg.setCertificatesList(pairList);

        List<CertificateEntry> entryList = new LinkedList<>();
        for (CertificatePair pair : msg.getCertificatesList()) {
            List<ExtensionMessage> extensionMessages = new LinkedList<>();
            int pointer = 0;
            while (pointer < pair.getExtensionsLength().getValue()) {
                ExtensionParser parser = ExtensionParserFactory.getExtensionParser(pair.getExtensions().getValue(),
                        pointer);
                extensionMessages.add(parser.parse());
                pointer = parser.getPointer();
            }
            Certificate certificate = parseCertificate(pair.getCertificateLength().getValue(), pair.getCertificate()
                    .getValue());
            entryList.add(new CertificateEntry(certificate, extensionMessages));
        }
        msg.setCertificatesListAsEntry(entryList);
    }

    private Certificate parseCertificate(int lengthBytes, byte[] bytesToParse) {
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(ArrayConverter
                    .intToBytes(lengthBytes + HandshakeByteLength.CERTIFICATES_LENGTH,
                            HandshakeByteLength.CERTIFICATES_LENGTH), ArrayConverter.intToBytes(lengthBytes,
                    HandshakeByteLength.CERTIFICATE_LENGTH), bytesToParse));
            return Certificate.parse(stream);
        } catch (IOException E) {
            LOGGER.warn("Could not parse Certificate bytes into Certificate object:"
                    + ArrayConverter.bytesToHexString(bytesToParse, false));
            return null;
        }
    }
}
