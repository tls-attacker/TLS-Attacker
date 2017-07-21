/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSL2ClientHelloSerializer extends ProtocolMessageSerializer {

    private final SSL2ClientHelloMessage msg;

    public SSL2ClientHelloSerializer(SSL2ClientHelloMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        appendInt(msg.getMessageLength().getValue(), SSL2ByteLength.LENGTH);
        appendByte(msg.getType().getValue());
        appendBytes(msg.getProtocolVersion().getValue());
        appendInt(msg.getCipherSuiteLength().getValue(), SSL2ByteLength.CIPHERSUITE_LENGTH);
        appendInt(msg.getSessionIDLength().getValue(), SSL2ByteLength.SESSIONID_LENGTH);
        appendInt(msg.getChallengeLength().getValue(), SSL2ByteLength.CHALLENGE_LENGTH);
        appendBytes(msg.getCipherSuites().getValue());
        appendBytes(msg.getSessionID().getValue());
        appendBytes(msg.getChallenge().getValue());
        return getAlreadySerialized();
    }

}
