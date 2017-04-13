/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.ssl.constants.SSLByteLength;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ProtocolMessageParser;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSL2ServerHelloParser extends ProtocolMessageParser {

    public SSL2ServerHelloParser(byte[] message, int pointer, ProtocolVersion selectedProtocolVersion) {
        super(pointer, message, selectedProtocolVersion);
    }

    @Override
    protected SSL2ServerHelloMessage parseMessageContent() {
        SSL2ServerHelloMessage message = new SSL2ServerHelloMessage();
        message.setMessageLength(parseIntField(SSLByteLength.LENGTH));
        message.setType(parseByteField(SSLByteLength.MESSAGE_TYPE));
        message.setSessionIdHit(parseByteField(SSLByteLength.SESSION_ID_HIT));
        message.setCertificateType(parseByteField(SSLByteLength.CERTIFICATE_TYPE));
        message.setProtocolVersion(parseByteArrayField(SSLByteLength.VERSION));
        message.setCertificateLength(parseIntField(SSLByteLength.CERTIFICATE_LENGTH));
        message.setCiphersuitesLength(parseIntField(SSLByteLength.CIPHERSUITE_LENGTH));
        message.setSessionIDLength(parseIntField(SSLByteLength.SESSIONID_LENGTH));
        message.setCertificate(parseByteArrayField(message.getCertificateLength().getValue()));
        message.setCipherSuites(parseByteArrayField(message.getCiphersuitesLength().getValue()));
        message.setSessionID(parseByteArrayField(message.getSessionIDLength().getValue()));
        return message;
    }

}
