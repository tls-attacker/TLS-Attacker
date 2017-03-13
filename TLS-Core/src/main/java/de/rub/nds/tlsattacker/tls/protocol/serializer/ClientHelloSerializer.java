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
import de.rub.nds.tlsattacker.tls.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientHelloSerializer extends HelloMessageSerializer<ClientHelloMessage> {

    private ClientHelloMessage message;

    public ClientHelloSerializer(ClientHelloMessage message, ProtocolVersion version) {
        super(message, version);
        this.message = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeProtocolVersion();
        writeUnixtime();
        writeRandom();
        writeSessionIDLength();
        writeSessionID();
        appendInt(message.getCipherSuiteLength().getValue(), HandshakeByteLength.CIPHER_SUITES_LENGTH);
        appendBytes(message.getCipherSuites().getValue());
        appendInt(message.getCompressionLength().getValue(), HandshakeByteLength.COMPRESSION_LENGTH);
        appendBytes(message.getCompressions().getValue());
        if (hasExtensionLengthField()) {
            appendInt(message.getExtensionsLength().getValue(), HandshakeByteLength.EXTENSION_LENGTH);
            if (hasExtensions()) {
                appendBytes(message.getExtensionBytes().getValue());
            }
        }
        return getAlreadySerialized();
    }

}
