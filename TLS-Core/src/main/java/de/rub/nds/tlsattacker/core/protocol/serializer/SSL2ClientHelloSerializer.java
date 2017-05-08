/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ssl.SSLByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;

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
        appendInt(msg.getMessageLength().getValue(), SSLByteLength.LENGTH);
        appendByte(msg.getType().getValue());
        appendBytes(msg.getProtocolVersion().getValue());
        appendInt(msg.getCipherSuiteLength().getValue(), SSLByteLength.CIPHERSUITE_LENGTH);
        appendInt(msg.getSessionIDLength().getValue(), SSLByteLength.SESSIONID_LENGTH);
        appendInt(msg.getChallengeLength().getValue(), SSLByteLength.CHALLENGE_LENGTH);
        appendBytes(msg.getCipherSuites().getValue());
        appendBytes(msg.getSessionID().getValue());
        appendBytes(msg.getChallenge().getValue());
        return getAlreadySerialized();
    }

}
