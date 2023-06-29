/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ClientMasterKeySerializer
        extends SSL2MessageSerializer<SSL2ClientMasterKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ClientMasterKeySerializer(SSL2ClientMasterKeyMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeMessageContent() {
        LOGGER.debug("Serializing SSL2ClientMasterKey");
        writeCipherKind();
        writeClearKeyLength();
        writeEncryptedKeyLength();
        writeKeyArgLength();
        writeClearKeyData();
        writeEncryptedKeyData();
        writeKeyArgData();
        return getAlreadySerialized();
    }

    private void writeEncryptedKeyData() {
        byte[] encryptedKeyData = message.getEncryptedKeyData().getValue();
        appendBytes(encryptedKeyData);
        LOGGER.debug("EncryptedKey: {}", encryptedKeyData);
    }

    private void writeClearKeyData() {
        byte[] clearKeyData = message.getClearKeyData().getValue();
        appendBytes(clearKeyData);
        LOGGER.debug("ClearKey: {}", clearKeyData);
    }

    private void writeEncryptedKeyLength() {
        int length = message.getEncryptedKeyLength().getValue();
        appendInt(length, SSL2ByteLength.ENCRYPTED_KEY_LENGTH);
        LOGGER.debug("EncryptedKeyLength: " + length);
    }

    public void writeKeyArgData() {
        byte[] keyArgData = message.getKeyArgData().getValue();
        appendBytes(keyArgData);
        LOGGER.debug("KeyArg: {}", keyArgData);
    }

    private void writeKeyArgLength() {
        int length = message.getKeyArgLength().getValue();
        appendInt(length, SSL2ByteLength.KEY_ARG_LENGTH);
        LOGGER.debug("EncryptedKeyLength: " + length);
    }

    private void writeClearKeyLength() {
        int length = message.getClearKeyLength().getValue();
        appendInt(length, SSL2ByteLength.CLEAR_KEY_LENGTH);
        LOGGER.debug("ClearKeyLength: " + length);
    }

    private void writeCipherKind() {
        byte[] cipherKindValue = message.getCipherKind().getValue();
        appendBytes(cipherKindValue);
        LOGGER.debug("CipherKind: " + Arrays.toString(cipherKindValue));
    }
}
