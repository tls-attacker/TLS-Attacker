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
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientHelloParser extends HelloParser<ClientHelloMessage> {

    public ClientHelloParser(int pointer, byte[] array) {
        super(pointer, array, HandshakeMessageType.CLIENT_HELLO);
    }

    @Override
    public ClientHelloMessage parse() {
        ClientHelloMessage message = new ClientHelloMessage();
        parseType(message);
        parseLength(message);
        parseProtocolVersion(message);
        parseUnixtime(message);
        parseRandom(message);
        parseSessionIDLength(message);
        parseSessionID(message);
        message.setCipherSuiteLength(parseIntField(HandshakeByteLength.CIPHER_SUITES_LENGTH));
        message.setCipherSuites(parseByteArrayField(message.getCipherSuiteLength().getValue()));
        message.setCompressionLength(parseIntField(HandshakeByteLength.COMPRESSION_LENGTH));
        message.setCompressions(parseByteArrayField(message.getCompressionLength().getValue()));
        if(hasExtensionLengthField(message))
        {
            parseExtensionLength(message);
            if(hasExtensions(message))
            {
                parseExtensionBytes(message);
            }
        }
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }
    
    
}
