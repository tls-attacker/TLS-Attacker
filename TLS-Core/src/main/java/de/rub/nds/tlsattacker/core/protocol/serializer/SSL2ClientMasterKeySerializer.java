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
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ClientMasterKeySerializer extends ProtocolMessageSerializer<SSL2ClientMasterKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SSL2ClientMasterKeyMessage msg;

    public SSL2ClientMasterKeySerializer(SSL2ClientMasterKeyMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing SSL2ClientMasterKey");
        writeMessageLength(msg);
        writeType(msg);
        writeCipherKind(msg);
        writeClearKeyLength(msg);
        writeEncryptedKeyLength(msg);
        writeKeyArgLength(msg);
        writeClearKeyData(msg);
        writeEncryptedKeyData(msg);
        return getAlreadySerialized();
    }

    private void writeEncryptedKeyData(SSL2ClientMasterKeyMessage msg) {
        byte[] encryptedKeyData = msg.getEncryptedKeyData().getValue();
        appendBytes(encryptedKeyData);
        LOGGER.debug("EncryptedKey: " + ArrayConverter.bytesToHexString(encryptedKeyData));
    }

    private void writeClearKeyData(SSL2ClientMasterKeyMessage msg) {
        byte[] clearKeyData = msg.getClearKeyData().getValue();
        appendBytes(clearKeyData);
        LOGGER.debug("ClearKey: " + ArrayConverter.bytesToHexString(clearKeyData));
    }

    private void writeEncryptedKeyLength(SSL2ClientMasterKeyMessage msg) {
        int length = msg.getEncryptedKeyLength().getValue();
        appendInt(length, SSL2ByteLength.ENCRYPTED_KEY_LENGTH);
        LOGGER.debug("EncryptedKeyLength: " + length);
    }

    private void writeKeyArgLength(SSL2ClientMasterKeyMessage msg) {
        int length = msg.getKeyArgLength().getValue();
        appendInt(length, SSL2ByteLength.ENCRYPTED_KEY_LENGTH);
        LOGGER.debug("EncryptedKeyLength: " + length);
    }

    private void writeClearKeyLength(SSL2ClientMasterKeyMessage msg) {
        int length = msg.getClearKeyLength().getValue();
        appendInt(length, SSL2ByteLength.CLEAR_KEY_LENGTH);
        LOGGER.debug("ClearKeyLength: " + length);
    }

    // TODO: Consider de-duplicating vs. SSL2ClientHelloSerializer.
    private void writeMessageLength(SSL2ClientMasterKeyMessage msg) {
        appendInt(msg.getMessageLength().getValue() ^ 0x8000, SSL2ByteLength.LENGTH);
        LOGGER.debug("MessageLength: " + msg.getMessageLength().getValue());
    }

    /**
     * Writes the Type of the SSL2ClientHello into the final byte[]
     */
    private void writeType(SSL2ClientMasterKeyMessage msg) {
        appendByte(msg.getType().getValue());
        LOGGER.debug("Type: " + msg.getType().getValue());
    }

    private void writeCipherKind(SSL2ClientMasterKeyMessage msg) {
        byte[] cipherKindValue = msg.getCipherKind().getValue();
        appendBytes(cipherKindValue);
        LOGGER.debug("CipherKind: " + Arrays.toString(cipherKindValue));
    }
}
