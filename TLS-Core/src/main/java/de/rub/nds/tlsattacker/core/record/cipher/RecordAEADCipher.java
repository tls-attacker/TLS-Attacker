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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import static de.rub.nds.tlsattacker.core.record.cipher.RecordCipher.LOGGER;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;

public class RecordAEADCipher extends RecordCipher {

    /**
     * sequence Number length in byte
     */
    public static final int SEQUENCE_NUMBER_LENGTH = 8;
    /**
     * tag length in byte
     */
    public static final int GCM_TAG_LENGTH = 16;
    /**
     * iv length in byte
     */
    public static final int GCM_IV_LENGTH = 12;

    public RecordAEADCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
        encryptCipher = CipherWrapper.getEncryptionCipher(cipherAlg);
        decryptCipher = CipherWrapper.getDecryptionCipher(cipherAlg);
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
            LOGGER.warn("Could not encrypt Data with the provided parameters. Returning unencrypted data.");
            LOGGER.debug(E);
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
            return new DecryptionResult(null, decrypted, null);
        } catch (CryptoException E) {
            LOGGER.warn("Could not decrypt Data with the provided parameters. Returning undecrypted data.");
            LOGGER.debug(E);
            return new DecryptionResult(null, decryptionRequest.getCipherText(), false);
        }
    }

    private EncryptionResult encryptTLS13(EncryptionRequest request) throws CryptoException {
        ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();

        byte[] sequenceNumberByte = ArrayConverter.longToBytes(context.getWriteSequenceNumber(),
                RecordByteLength.SEQUENCE_NUMBER);
        byte[] nonce = ArrayConverter.concatenate(new byte[GCM_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                sequenceNumberByte);
        byte[] encryptIV = prepareAeadParameters(nonce, getEncryptionIV());
        LOGGER.debug("Encrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(encryptIV));
        byte[] cipherText = encryptCipher.encrypt(getKeySet().getWriteKey(localConEndType), encryptIV,
                GCM_TAG_LENGTH * 8, request.getPlainText());
        return new EncryptionResult(encryptIV, cipherText, false);
    }

    private byte[] prepareAeadParameters(byte[] nonce, byte[] iv) {
        byte[] param = new byte[GCM_IV_LENGTH];
        for (int i = 0; i < GCM_IV_LENGTH; i++) {
            param[i] = (byte) (iv[i] ^ nonce[i]);
        }
        return param;
    }

    private EncryptionResult encryptTLS12(EncryptionRequest request) throws CryptoException {
        ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();

        byte[] nonce = ArrayConverter.longToBytes(context.getWriteSequenceNumber(), RecordByteLength.SEQUENCE_NUMBER);
        byte[] iv = ArrayConverter.concatenate(
                getKeySet().getWriteIv(context.getConnection().getLocalConnectionEndType()), nonce);
        LOGGER.debug("Encrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(iv));
        LOGGER.debug("Encrypting GCM with the following AAD: {}",
                ArrayConverter.bytesToHexString(request.getAdditionalAuthenticatedData()));
        byte[] ciphertext = encryptCipher.encrypt(getKeySet().getWriteKey(localConEndType), iv, GCM_TAG_LENGTH * 8,
                request.getAdditionalAuthenticatedData(), request.getPlainText());
        return new EncryptionResult(iv, ArrayConverter.concatenate(nonce, ciphertext), false);
    }

    private byte[] decryptTLS13(DecryptionRequest decryptionRequest) throws CryptoException {
        ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
        LOGGER.debug("Decrypting using SQN:" + context.getReadSequenceNumber());
        byte[] sequenceNumberByte = ArrayConverter.longToBytes(context.getReadSequenceNumber(),
                RecordByteLength.SEQUENCE_NUMBER);
        byte[] nonce = ArrayConverter.concatenate(new byte[GCM_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                sequenceNumberByte);
        byte[] decryptIV = prepareAeadParameters(nonce, getDecryptionIV());
        LOGGER.debug("Decrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(decryptIV));
        LOGGER.debug("Decrypting the following GCM ciphertext: {}",
                ArrayConverter.bytesToHexString(decryptionRequest.getCipherText()));
        return decryptCipher.decrypt(getKeySet().getReadKey(localConEndType), decryptIV, GCM_TAG_LENGTH * 8,
                decryptionRequest.getCipherText());
    }

    private byte[] decryptTLS12(DecryptionRequest decryptionRequest) throws CryptoException {
        ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
        if (decryptionRequest.getCipherText().length < SEQUENCE_NUMBER_LENGTH) {
            LOGGER.warn("Could not DecryptCipherText. Too short. Returning undecrypted Ciphertext");
            return decryptionRequest.getCipherText();
        }
        byte[] nonce = Arrays.copyOf(decryptionRequest.getCipherText(), SEQUENCE_NUMBER_LENGTH);
        byte[] data = Arrays.copyOfRange(decryptionRequest.getCipherText(), SEQUENCE_NUMBER_LENGTH,
                decryptionRequest.getCipherText().length);
        byte[] iv = ArrayConverter.concatenate(
                getKeySet().getReadIv(context.getConnection().getLocalConnectionEndType()), nonce);
        LOGGER.debug("Decrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(iv));
        LOGGER.debug("Decrypting GCM with the following AAD: {}",
                ArrayConverter.bytesToHexString(decryptionRequest.getAdditionalAuthenticatedData()));
        LOGGER.debug("Decrypting the following GCM ciphertext: {}", ArrayConverter.bytesToHexString(data));
        return decryptCipher.decrypt(getKeySet().getReadKey(localConEndType), iv, GCM_TAG_LENGTH * 8,
                decryptionRequest.getAdditionalAuthenticatedData(), data);
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
        return SEQUENCE_NUMBER_LENGTH + GCM_TAG_LENGTH;
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
