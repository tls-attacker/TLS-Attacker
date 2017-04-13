/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateMessageSerializer extends HandshakeMessageSerializer<CertificateMessage> {

    private final CertificateMessage msg;

    /**
     * Constructor for the CertificateMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public CertificateMessageSerializer(CertificateMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeCertificateLength(msg);
        writeX509Certificate(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the CertificateLength of the CertificateMessage into the final
     * byte[]
     */
    private void writeCertificateLength(CertificateMessage msg) {
        appendInt(msg.getCertificatesLength().getValue(), HandshakeByteLength.CERTIFICATES_LENGTH);
        LOGGER.debug("CertificateLength: " + msg.getCertificatesLength().getValue());
    }

    /**
     * Writes the X509Certificate of the CertificateMessage into the final
     * byte[]
     */
    private void writeX509Certificate(CertificateMessage msg) {
        appendBytes(msg.getX509CertificateBytes().getValue());
        LOGGER.debug("X509Certificate: " + ArrayConverter.bytesToHexString(msg.getX509CertificateBytes().getValue()));
    }

}
