/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordAEADCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * sequence Number length in bytes
     */
    public static final int SEQUENCE_NUMBER_LENGTH = 8;

    /**
     * AEAD tag length in bytes for regular ciphers
     */
    public static final int AEAD_TAG_LENGTH = 16;

    /**
     * AEAD tag length in bytes for CCM_8 ciphers
     */
    public static final int AEAD_CCM_8_TAG_LENGTH = 8;

    /**
     * AEAD iv length in bytes
     */
    public static final int AEAD_IV_LENGTH = 12;

    /**
     * Stores the computed tag length
     */
    private final int aeadTagLength;

    public RecordAEADCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
        encryptCipher = CipherWrapper.getEncryptionCipher(cipherSuite, localConEndType, getKeySet());
        decryptCipher = CipherWrapper.getDecryptionCipher(cipherSuite, localConEndType, getKeySet());

        if (cipherSuite.isCCM_8()) {
            aeadTagLength = AEAD_CCM_8_TAG_LENGTH;
        } else {
            aeadTagLength = AEAD_TAG_LENGTH;
        }
    }

    @Override
    public EncryptionResult encrypt(EncryptionRequest request) {
        try {
            if (version.isTLS13() || context.getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
                return encryptTLS13(request);
            } else {
                return encryptTLS12(request);
            }
        } catch (CryptoException E) {
            LOGGER.warn("Could not encrypt Data with the provided parameters. Returning unencrypted data.", E);
            return new EncryptionResult(request.getPlainText());
        }
    }

    @Override
    public DecryptionResult decrypt(DecryptionRequest decryptionRequest) {
        try {
            byte[] decrypted;
            if (version.isTLS13() || context.getActiveKeySetTypeRead() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
                decrypted = decryptTLS13(decryptionRequest);
            } else {
                decrypted = decryptTLS12(decryptionRequest);
            }
            return new DecryptionResult(null, decrypted, null, true);
        } catch (CryptoException E) {
            LOGGER.warn("Could not decrypt Data with the provided parameters. Returning undecrypted data.");
            LOGGER.debug(E);
            return new DecryptionResult(null, decryptionRequest.getCipherText(), false, false);
        }
    }

    private EncryptionResult encryptTLS13(EncryptionRequest request) throws CryptoException {
        byte[] sequenceNumberBytes = ArrayConverter.longToBytes(context.getWriteSequenceNumber(),
                RecordByteLength.SEQUENCE_NUMBER);
        LOGGER.debug("SQN bytes: " + ArrayConverter.bytesToHexString(sequenceNumberBytes));
        byte[] nonce = ArrayConverter.concatenate(new byte[AEAD_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                sequenceNumberBytes);
        LOGGER.debug("NonceBytes:" + ArrayConverter.bytesToHexString(nonce));

        byte[] encryptIV = prepareAeadParameters(nonce, getEncryptionIV());
        LOGGER.debug("Encrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(encryptIV));
        byte[] cipherText;
        if (version == ProtocolVersion.TLS13 || version == ProtocolVersion.TLS13_DRAFT25
                || version == ProtocolVersion.TLS13_DRAFT26 || version == ProtocolVersion.TLS13_DRAFT27
                || version == ProtocolVersion.TLS13_DRAFT28) {
            LOGGER.debug("AAD:" + ArrayConverter.bytesToHexString(request.getAdditionalAuthenticatedData()));
            cipherText = encryptCipher.encrypt(encryptIV, aeadTagLength * 8, request.getAdditionalAuthenticatedData(),
                    request.getPlainText());
        } else {
            cipherText = encryptCipher.encrypt(encryptIV, aeadTagLength * 8, request.getPlainText());
        }
        return new EncryptionResult(encryptIV, cipherText, false);
    }

    /**
     * Used to prepare AAD for TLS1.3 only!
     */
    private byte[] prepareAeadParameters(byte[] nonce, byte[] iv) {
        byte[] param = new byte[AEAD_IV_LENGTH];
        for (int i = 0; i < AEAD_IV_LENGTH; i++) {
            param[i] = (byte) (iv[i] ^ nonce[i]);
        }
        return param;
    }

    private EncryptionResult encryptTLS12(EncryptionRequest request) throws CryptoException {
        byte[] nonce = ArrayConverter.longToBytes(context.getWriteSequenceNumber(), SEQUENCE_NUMBER_LENGTH);
        byte[] iv = ArrayConverter.concatenate(
                getKeySet().getWriteIv(context.getConnection().getLocalConnectionEndType()), nonce);
        LOGGER.debug("Encrypting AEAD with the following IV: {}", ArrayConverter.bytesToHexString(iv));
        LOGGER.debug("Encrypting AEAD with the following AAD: {}",
                ArrayConverter.bytesToHexString(request.getAdditionalAuthenticatedData()));
        byte[] ciphertext = encryptCipher.encrypt(iv, aeadTagLength * 8, request.getAdditionalAuthenticatedData(),
                request.getPlainText());
        if (cipherSuite.usesStrictExplicitIv()) {
            return new EncryptionResult(ciphertext);
        } else {
            return new EncryptionResult(iv, ArrayConverter.concatenate(nonce, ciphertext), false);
        }
    }

    private byte[] decryptTLS13(DecryptionRequest decryptionRequest) throws CryptoException {
        LOGGER.debug("Decrypting using SQN:" + context.getReadSequenceNumber());
        byte[] sequenceNumberByte = ArrayConverter.longToBytes(context.getReadSequenceNumber(),
                RecordByteLength.SEQUENCE_NUMBER);
        byte[] nonce = ArrayConverter
                .concatenate(new byte[AEAD_IV_LENGTH - SEQUENCE_NUMBER_LENGTH], sequenceNumberByte);
        byte[] decryptIV = prepareAeadParameters(nonce, getDecryptionIV());
        LOGGER.debug("Decrypting AEAD with the following IV: {}", ArrayConverter.bytesToHexString(decryptIV));
        LOGGER.debug("Decrypting the following AEAD ciphertext: {}",
                ArrayConverter.bytesToHexString(decryptionRequest.getCipherText()));
        if (version == ProtocolVersion.TLS13 || version == ProtocolVersion.TLS13_DRAFT25
                || version == ProtocolVersion.TLS13_DRAFT26 || version == ProtocolVersion.TLS13_DRAFT27
                || version == ProtocolVersion.TLS13_DRAFT28) {
            return decryptCipher.decrypt(decryptIV, aeadTagLength * 8,
                    decryptionRequest.getAdditionalAuthenticatedData(), decryptionRequest.getCipherText());
        } else {
            return decryptCipher.decrypt(decryptIV, aeadTagLength * 8, decryptionRequest.getCipherText());
        }
    }

    private byte[] decryptTLS12(DecryptionRequest decryptionRequest) throws CryptoException {
        if (decryptionRequest.getCipherText().length < SEQUENCE_NUMBER_LENGTH) {
            LOGGER.warn("Could not decrypt ciphertext. Too short. Returning undecrypted Ciphertext");
            return decryptionRequest.getCipherText();
        }
        byte[] nonce;
        byte[] data;
        if (cipherSuite.usesStrictExplicitIv()) {
            // TODO In the case of DTLS, we should get the sequence number from
            // the record
            nonce = ArrayConverter.longToBytes(context.getReadSequenceNumber(), SEQUENCE_NUMBER_LENGTH);
            data = decryptionRequest.getCipherText();
        } else {
            nonce = Arrays.copyOf(decryptionRequest.getCipherText(), SEQUENCE_NUMBER_LENGTH);
            data = Arrays.copyOfRange(decryptionRequest.getCipherText(), SEQUENCE_NUMBER_LENGTH,
                    decryptionRequest.getCipherText().length);
        }
        byte[] iv = ArrayConverter.concatenate(
                getKeySet().getReadIv(context.getConnection().getLocalConnectionEndType()), nonce);
        LOGGER.debug("Decrypting AEAD with the following IV: {}", ArrayConverter.bytesToHexString(iv));
        LOGGER.debug("Decrypting AEAD with the following AAD: {}",
                ArrayConverter.bytesToHexString(decryptionRequest.getAdditionalAuthenticatedData()));

        LOGGER.debug("Decrypting the following ciphertext: {}", ArrayConverter.bytesToHexString(data));
        return decryptCipher.decrypt(iv, aeadTagLength * 8, decryptionRequest.getAdditionalAuthenticatedData(), data);
    }

    @Override
    public boolean isUsingPadding() {
        return version.isTLS13() || context.getActiveKeySetTypeWrite() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS
                || context.getActiveKeySetTypeRead() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS;
    }

    @Override
    public boolean isUsingMac() {
        return false;
    }

    @Override
    public boolean isUsingTags() {
        return true;
    }

    @Override
    public int getTagSize() {
        if (cipherSuite.usesStrictExplicitIv() || version.isTLS13()) {
            return aeadTagLength;
        } else {
            return SEQUENCE_NUMBER_LENGTH + aeadTagLength;
        }
    }

    @Override
    public byte[] getEncryptionIV() {
        byte[] nonce = ArrayConverter.longToBytes(context.getWriteSequenceNumber(), SEQUENCE_NUMBER_LENGTH);
        return ArrayConverter.concatenate(getKeySet().getWriteIv(context.getConnection().getLocalConnectionEndType()),
                nonce);
    }

    @Override
    public byte[] getDecryptionIV() {
        byte[] nonce = ArrayConverter.longToBytes(context.getReadSequenceNumber(), SEQUENCE_NUMBER_LENGTH);
        return ArrayConverter.concatenate(getKeySet().getReadIv(context.getConnection().getLocalConnectionEndType()),
                nonce);
    }
}
