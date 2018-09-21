/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloRetryRequestSerializer extends HandshakeMessageSerializer<HelloRetryRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HelloRetryRequestMessage msg;

    public HelloRetryRequestSerializer(HelloRetryRequestMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        writeProtocolVersion();
        writeSelectedCiphersuite();
        if (hasExtensionLengthField()) {
            writeExtensionLength();
            if (hasExtensions()) {
                writeExtensionBytes();
            }
        }
        return getAlreadySerialized();
    }

    protected void writeProtocolVersion() {
        appendBytes(msg.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

    protected void writeSelectedCiphersuite() {
        appendBytes(msg.getSelectedCipherSuite().getValue());
        LOGGER.debug("SelectedCipherSuite: " + ArrayConverter.bytesToHexString(msg.getSelectedCipherSuite().getValue()));
    }
}
