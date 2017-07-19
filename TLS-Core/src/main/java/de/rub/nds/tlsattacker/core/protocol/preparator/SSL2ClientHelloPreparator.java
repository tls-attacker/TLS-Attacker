/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSL2ClientHelloPreparator extends ProtocolMessagePreparator {

    private final SSL2ClientHelloMessage message;

    public SSL2ClientHelloPreparator(TlsContext context, SSL2ClientHelloMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        message.setType(HandshakeMessageType.CLIENT_HELLO.getValue());
        message.setProtocolVersion(context.getConfig().getHighestProtocolVersion().getValue());
        // By Default we just set a fixed value with ssl2 ciphersuites
        message.setCipherSuites(ArrayConverter.hexStringToByteArray("0700c0060040050080040080030080020080010080080080"));
        byte[] challenge = new byte[16];
        RandomHelper.getRandom().nextBytes(challenge);
        message.setChallenge(challenge);
        message.setSessionID(context.getSessionID());
        message.setSessionIDLength(message.getSessionID().getValue().length);
        message.setChallengeLength(message.getChallenge().getValue().length);
        message.setCipherSuiteLength(message.getCipherSuites().getValue().length);
        int length = SSL2ByteLength.CHALLENGE_LENGTH + SSL2ByteLength.CIPHERSUITE_LENGTH + SSL2ByteLength.MESSAGE_TYPE
                + SSL2ByteLength.SESSIONID_LENGTH;
        length += message.getChallenge().getValue().length;
        length += message.getCipherSuites().getValue().length;
        length += message.getSessionID().getValue().length;
        length += message.getProtocolVersion().getValue().length;
        message.setMessageLength(length ^ 0x8000);
    }

}
