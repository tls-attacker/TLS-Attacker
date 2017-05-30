/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ssl.SSLByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
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
        msg.setMessageLength(parseIntField(SSLByteLength.LENGTH));
        msg.setType(parseByteField(SSLByteLength.MESSAGE_TYPE));
        msg.setProtocolVersion(parseByteArrayField(SSLByteLength.VERSION));
        msg.setCipherSuiteLength(parseIntField(SSLByteLength.CIPHERSUITE_LENGTH));
        msg.setSessionIDLength(parseIntField(SSLByteLength.SESSIONID_LENGTH));
        msg.setChallengeLength(parseIntField(SSLByteLength.CHALLENGE_LENGTH));
        msg.setCipherSuites(parseByteArrayField(msg.getCipherSuiteLength().getValue()));
        msg.setSessionID(parseByteArrayField(msg.getSessionIDLength().getValue()));
        msg.setChallenge(parseByteArrayField(msg.getChallengeLength().getValue()));
        return msg;
    }
}
