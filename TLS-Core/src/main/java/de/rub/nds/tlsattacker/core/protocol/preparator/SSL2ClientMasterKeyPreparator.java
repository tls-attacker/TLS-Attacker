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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ClientMasterKeyPreparator extends ProtocolMessagePreparator<SSL2ClientMasterKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final int EXPORT_RC4_NUM_OF_SECRET_KEY_BYTES = 5;
    public static final int EXPORT_RC4_NUM_OF_CLEAR_KEY_BYTES = 11;

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
        LOGGER.debug("Prepare SSL2ClientMasterKey");
        prepareType(message);
        prepareCipherKind(message);
        prepareClearKey(message);
        prepareClearKeyLength(message);
        prepareKeyArgLength(message);
        // TODO: Add keyArgData if we want to also support block ciphers.

        LOGGER.debug("RSA Modulus: " + chooser.getServerRsaModulus().toString());

        prepareRSACiphertext(message);

        final int lengthFieldLength = 2;
        int length = SSL2ByteLength.MESSAGE_TYPE;
        length += message.getCipherKind().getValue().length;
        length += message.getClearKeyData().getValue().length + lengthFieldLength;
        length += message.getEncryptedKeyData().getValue().length + lengthFieldLength;
        length += lengthFieldLength; // for keyArgLength
        prepareMessageLength(message, length);
    }

    private void prepareKeyArgLength(SSL2ClientMasterKeyMessage message2) {
        message.setKeyArgLength(0);
        LOGGER.debug("KeyArgLength: " + message.getKeyArgLength().getValue());
    }

    private void prepareType(SSL2ClientMasterKeyMessage message) {
        message.setType(HandshakeMessageType.SSL2_CLIENT_MASTER_KEY.getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }

    private void prepareCipherKind(SSL2ClientMasterKeyMessage message) {
        // by default we currently just try export RC4
        message.setCipherKind(ArrayConverter.hexStringToByteArray("020080"));
        LOGGER.debug("CipherKind: " + ArrayConverter.bytesToHexString(message.getCipherKind().getValue()));
    }

    private void prepareClearKey(SSL2ClientMasterKeyMessage message) {
        // by default we currently supply null bytes as the clear key portion
        message.setClearKeyData(new byte[EXPORT_RC4_NUM_OF_CLEAR_KEY_BYTES]);
        LOGGER.debug("ClearKey: " + ArrayConverter.bytesToHexString(message.getClearKeyData().getValue()));
    }

    private void prepareClearKeyLength(SSL2ClientMasterKeyMessage message) {
        message.setClearKeyLength(message.getClearKeyData().getValue().length);
        LOGGER.debug("ClearKeyLength: " + message.getClearKeyLength().getValue());
    }

    private void prepareMessageLength(SSL2ClientMasterKeyMessage message, int length) {
        message.setMessageLength(length);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

    protected void preparePadding(SSL2ClientMasterKeyMessage msg) {
        msg.getComputations().setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(msg.getComputations().getPadding().getValue()));
    }

    private byte[] generatePremasterSecret() {
        byte[] tempPremasterSecret = new byte[EXPORT_RC4_NUM_OF_SECRET_KEY_BYTES];
        chooser.getContext().getRandom().nextBytes(tempPremasterSecret);
        return tempPremasterSecret;
    }

    protected void preparePremasterSecret(SSL2ClientMasterKeyMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    protected void preparePlainPaddedPremasterSecret(SSL2ClientMasterKeyMessage msg) {
        msg.getComputations().setPlainPaddedPremasterSecret(
                ArrayConverter.concatenate(new byte[] { 0x00, 0x02 }, padding, new byte[] { 0x00 }, msg
                        .getComputations().getPremasterSecret().getValue()));
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

        int keyByteLength = chooser.getServerRsaModulus().bitLength() / 8;
        // the number of random bytes in the pkcs1 message

        int unpaddedLength = EXPORT_RC4_NUM_OF_SECRET_KEY_BYTES;
        // Currently we only support 40-bit export RC4

        int randomByteLength = keyByteLength - unpaddedLength - 3;
        padding = new byte[randomByteLength];
        chooser.getContext().getRandom().nextBytes(padding);
        ArrayConverter.makeArrayNonZero(padding);
        preparePadding(message);
        premasterSecret = generatePremasterSecret();
        preparePremasterSecret(message);
        preparePlainPaddedPremasterSecret(message);

        byte[] paddedPremasterSecret = message.getComputations().getPlainPaddedPremasterSecret().getValue();

        BigInteger biPaddedPremasterSecret = new BigInteger(1, paddedPremasterSecret);
        BigInteger biEncrypted = biPaddedPremasterSecret.modPow(chooser.getServerRSAPublicKey(),
                chooser.getServerRsaModulus());
        encryptedPremasterSecret = ArrayConverter.bigIntegerToByteArray(biEncrypted, chooser.getServerRsaModulus()
                .bitLength() / 8, true);
        prepareEncryptedKeyData(message);
        prepareEncryptedKeyDataLength(message);
    }

}
