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
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSL2ClientHelloParser extends ProtocolMessageParser {

    public SSL2ClientHelloParser(byte[] message, int pointer, ProtocolVersion version) {
        super(pointer, message, version);
    }

    @Override
    protected SSL2ClientHelloMessage parseMessageContent() {
        SSL2ClientHelloMessage msg = new SSL2ClientHelloMessage();
        msg.setMessageLength(parseIntField(SSL2ByteLength.LENGTH));
        msg.setType(parseByteField(SSL2ByteLength.MESSAGE_TYPE));
        msg.setProtocolVersion(parseByteArrayField(SSL2ByteLength.VERSION));
        msg.setCipherSuiteLength(parseIntField(SSL2ByteLength.CIPHERSUITE_LENGTH));
        msg.setSessionIDLength(parseIntField(SSL2ByteLength.SESSIONID_LENGTH));
        msg.setChallengeLength(parseIntField(SSL2ByteLength.CHALLENGE_LENGTH));
        msg.setCipherSuites(parseByteArrayField(msg.getCipherSuiteLength().getValue()));
        msg.setSessionID(parseByteArrayField(msg.getSessionIDLength().getValue()));
        msg.setChallenge(parseByteArrayField(msg.getChallengeLength().getValue()));
        return msg;
    }
}
