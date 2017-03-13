/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateMessageParser extends HandshakeMessageParser<CertificateMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    public CertificateMessageParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, HandshakeMessageType.CERTIFICATE, version);
    }

    @Override
    protected void parseHandshakeMessageContent(CertificateMessage msg) {
        msg.setCertificatesLength(parseIntField(HandshakeByteLength.CERTIFICATES_LENGTH));
        msg.setX509CertificateBytes(parseByteArrayField(msg.getCertificatesLength().getValue()));
    }

    @Override
    protected CertificateMessage createHandshakeMessage() {
        return new CertificateMessage();
    }

}
