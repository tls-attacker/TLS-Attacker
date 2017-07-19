/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;

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
        message.setMessageLength(parseIntField(SSL2ByteLength.LENGTH));
        message.setType(parseByteField(SSL2ByteLength.MESSAGE_TYPE));
        message.setSessionIdHit(parseByteField(SSL2ByteLength.SESSION_ID_HIT));
        message.setCertificateType(parseByteField(SSL2ByteLength.CERTIFICATE_TYPE));
        message.setProtocolVersion(parseByteArrayField(SSL2ByteLength.VERSION));
        message.setCertificateLength(parseIntField(SSL2ByteLength.CERTIFICATE_LENGTH));
        message.setCiphersuitesLength(parseIntField(SSL2ByteLength.CIPHERSUITE_LENGTH));
        message.setSessionIDLength(parseIntField(SSL2ByteLength.SESSIONID_LENGTH));
        message.setCertificate(parseByteArrayField(message.getCertificateLength().getValue()));
        message.setCipherSuites(parseByteArrayField(message.getCiphersuitesLength().getValue()));
        message.setSessionID(parseByteArrayField(message.getSessionIDLength().getValue()));
        return message;
    }

}
