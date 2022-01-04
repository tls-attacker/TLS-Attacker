/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ClientMasterKeyPreparator extends HandshakeMessagePreparator<SSL2ClientMasterKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SSL2ClientMasterKeyMessage message;

    private byte[] padding;

    private byte[] premasterSecret;

    private byte[] encryptedPremasterSecret;

    public SSL2ClientMasterKeyPreparator(Chooser chooser, SSL2ClientMasterKeyMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        prepareHandshakeMessageContents();
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        LOGGER.debug("Prepare SSL2ClientMasterKey");
        prepareMessagePaddingLength(message);
        prepareType(message);
        prepareCipherKind(message);
        prepareClearKey(message);
        prepareClearKeyLength(message);
        prepareKeyArg(message);
        prepareKeyArgLength(message);

        LOGGER.debug("RSA Modulus: " + chooser.getServerRsaModulus().toString());

        prepareRSACiphertext(message);

        final int lengthFieldLength = 2;
        int length = SSL2ByteLength.MESSAGE_TYPE;
        length += message.getCipherKind().getValue().length;
        length += message.getClearKeyData().getValue().length + SSL2ByteLength.CLEAR_KEY_LENGTH;
        length += message.getEncryptedKeyData().getValue().length + SSL2ByteLength.ENCRYPTED_KEY_LENGTH;
        length += message.getKeyArgData().getValue().length + SSL2ByteLength.KEY_ARG_LENGTH;
        prepareMessageLength(message, length);
    }

    /**
     * Sets the padding length of the message (record). It is always 0, because the message is clear-text. This has
     * nothing to do with PKCS#1 padding for the Premaster Secret as processed by preparePadding().
     */
    private void prepareMessagePaddingLength(SSL2ClientMasterKeyMessage message) {
        message.setPaddingLength(0);
        LOGGER.debug("MessagePaddingLength: " + message.getPaddingLength().getValue());
    }

    private void prepareType(SSL2ClientMasterKeyMessage message) {
        message.setType(HandshakeMessageType.SSL2_CLIENT_MASTER_KEY.getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }

    private void prepareCipherKind(SSL2ClientMasterKeyMessage message) {
        message.setCipherKind(chooser.getSSL2CipherSuite().getByteValue());
        LOGGER.debug("CipherKind: " + ArrayConverter.bytesToHexString(message.getCipherKind().getValue()));
    }

    private void prepareClearKey(SSL2ClientMasterKeyMessage message) {
        // by default we currently supply null bytes as the clear key portion
        message.setClearKeyData(new byte[chooser.getSSL2CipherSuite().getClearKeyByteNumber()]);
        LOGGER.debug("ClearKey: " + ArrayConverter.bytesToHexString(message.getClearKeyData().getValue()));
    }

    private void prepareClearKeyLength(SSL2ClientMasterKeyMessage message) {
        message.setClearKeyLength(message.getClearKeyData().getValue().length);
        LOGGER.debug("ClearKeyLength: " + message.getClearKeyLength().getValue());
    }

    private void prepareKeyArg(SSL2ClientMasterKeyMessage message) {
        // KEY-ARG-DATA contains the IV for block ciphers
        byte[] keyArgData = new byte[chooser.getSSL2CipherSuite().getBlockSize()];
        chooser.getContext().getRandom().nextBytes(keyArgData);
        message.setKeyArgData(keyArgData);
        LOGGER.debug("KeyArg: " + ArrayConverter.bytesToHexString(keyArgData));
    }

    private void prepareKeyArgLength(SSL2ClientMasterKeyMessage message) {
        message.setKeyArgLength(message.getKeyArgData().getValue().length);
        LOGGER.debug("KeyArgLength: " + message.getKeyArgLength().getValue());
    }

    private void prepareMessageLength(SSL2ClientMasterKeyMessage message, int length) {
        message.setMessageLength(length);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

    protected void preparePadding(SSL2ClientMasterKeyMessage msg) {
        msg.getComputations().setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(msg.getComputations().getPadding().getValue()));
    }

    /**
     * Generates as many random bytes as required for the secret portion of the master key in the chosen cipher suite.
     */
    private byte[] generatePremasterSecret() {
        byte[] tempPremasterSecret = new byte[chooser.getSSL2CipherSuite().getSecretKeyByteNumber()];
        chooser.getContext().getRandom().nextBytes(tempPremasterSecret);
        return tempPremasterSecret;
    }

    protected void preparePremasterSecret(SSL2ClientMasterKeyMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
            + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    protected void preparePlainPaddedPremasterSecret(SSL2ClientMasterKeyMessage msg) {
        msg.getComputations().setPlainPaddedPremasterSecret(ArrayConverter.concatenate(new byte[] { 0x00, 0x02 },
            padding, new byte[] { 0x00 }, msg.getComputations().getPremasterSecret().getValue()));
        LOGGER.debug("PlainPaddedPremasterSecret: "
            + ArrayConverter.bytesToHexString(msg.getComputations().getPlainPaddedPremasterSecret().getValue()));
    }

    protected void prepareEncryptedKeyData(SSL2ClientMasterKeyMessage msg) {
        msg.setEncryptedKeyData(encryptedPremasterSecret);
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getEncryptedKeyData().getValue()));
    }

    protected void prepareEncryptedKeyDataLength(SSL2ClientMasterKeyMessage msg) {
        msg.setEncryptedKeyLength(msg.getEncryptedKeyData().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getEncryptedKeyLength().getValue());
    }

    private void prepareRSACiphertext(SSL2ClientMasterKeyMessage message) {
        // TODO: Maybe de-duplicate vs. RSAClientKeyExchangePreparator
        message.prepareComputations();

        // The Premaster Secret is actually called SECRET-KEY-DATA in SSLv2, but
        // its role is similar
        premasterSecret = generatePremasterSecret();
        preparePremasterSecret(message);

        // the number of random bytes in the pkcs1 message
        int keyByteLength = chooser.getServerRsaModulus().bitLength() / Bits.IN_A_BYTE;

        int unpaddedLength = message.getComputations().getPremasterSecret().getValue().length;

        int randomByteLength = keyByteLength - unpaddedLength - 3;
        if (randomByteLength >= 0) {
            padding = new byte[randomByteLength];
        } else {
            padding = new byte[0]; // randomByteLength could be negative
        }
        chooser.getContext().getRandom().nextBytes(padding);
        ArrayConverter.makeArrayNonZero(padding);
        preparePadding(message);

        preparePlainPaddedPremasterSecret(message);
        byte[] paddedPremasterSecret = message.getComputations().getPlainPaddedPremasterSecret().getValue();

        BigInteger biPaddedPremasterSecret = new BigInteger(1, paddedPremasterSecret);
        BigInteger biEncrypted =
            biPaddedPremasterSecret.modPow(chooser.getServerRSAPublicKey(), chooser.getServerRsaModulus());
        encryptedPremasterSecret = ArrayConverter.bigIntegerToByteArray(biEncrypted,
            chooser.getServerRsaModulus().bitLength() / Bits.IN_A_BYTE, true);
        prepareEncryptedKeyData(message);
        prepareEncryptedKeyDataLength(message);
    }

}
