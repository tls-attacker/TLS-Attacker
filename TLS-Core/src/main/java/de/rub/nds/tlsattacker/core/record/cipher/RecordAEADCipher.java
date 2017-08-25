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
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import static de.rub.nds.tlsattacker.core.record.cipher.RecordCipher.LOGGER;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Robert Merget <robert.merget@rub.de>
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
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
    /**
     * client secret
     */
    private byte[] clientSecret;
    /**
     * server secret
     */
    private byte[] serverSecret;
    /**
     * client encryption IV
     */
    private byte[] clientWriteIv;
    /**
     * server encryption IV
     */
    private byte[] serverWriteIv;

    private GCMParameterSpec encryptIV;

    private GCMParameterSpec decryptIV;

    private SecretKey encryptKey;

    private SecretKey decryptKey;

    public RecordAEADCipher(TlsContext context) {
        super(0);
        this.tlsContext = context;
        init();
    }

    private void init() {
        ProtocolVersion protocolVersion = tlsContext.getChooser().getSelectedProtocolVersion();
        CipherSuite cipherSuite = tlsContext.getChooser().getSelectedCipherSuite();
        try {
            bulkCipherAlg = BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherSuite);
            CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
            encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            if (protocolVersion.isTLS13()) {
                initForTLS13(cipherSuite, cipherAlg);
            } else {
                initForTLS12(cipherSuite, cipherAlg);
            }
            if (tlsContext.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
                encryptKey = new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName());
                decryptKey = new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName());
            } else {
                decryptKey = new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName());
                encryptKey = new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName());
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new CryptoException("Could not initialize RecordAEADCipher", ex);
        }
    }

    private void initForTLS12(CipherSuite cipherSuite, CipherAlgorithm cipherAlg) throws NoSuchAlgorithmException,
            NoSuchPaddingException {
        int keySize = cipherAlg.getKeySize();
        encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
        decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
        // GCM in TLS uses 4 bytes long salt (generated in the handshake),
        // 8 bytes long nonce (changed for each new record), and 4 bytes long
        // sequence number used increased in the record
        int saltSize = GCM_IV_LENGTH - SEQUENCE_NUMBER_LENGTH;
        int secretSetSize = 2 * keySize + 2 * saltSize;
        byte[] masterSecret = tlsContext.getMasterSecret();
        byte[] seed = ArrayConverter.concatenate(tlsContext.getServerRandom(), tlsContext.getClientRandom());

        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getChooser()
                .getSelectedProtocolVersion(), cipherSuite);
        byte[] keyBlock = PseudoRandomFunction.compute(prfAlgorithm, masterSecret,
                PseudoRandomFunction.KEY_EXPANSION_LABEL, seed, secretSetSize);
        LOGGER.debug("A new key block was generated: {}", ArrayConverter.bytesToHexString(keyBlock));
        int offset = 0;
        clientWriteKey = Arrays.copyOfRange(keyBlock, offset, offset + keySize);
        offset += keySize;
        LOGGER.debug("Client write key: {}", ArrayConverter.bytesToHexString(clientWriteKey));
        serverWriteKey = Arrays.copyOfRange(keyBlock, offset, offset + keySize);
        offset += keySize;
        LOGGER.debug("Server write key: {}", ArrayConverter.bytesToHexString(serverWriteKey));
        clientWriteIv = Arrays.copyOfRange(keyBlock, offset, offset + saltSize);
        offset += saltSize;
        LOGGER.debug("Client write IV: {}", ArrayConverter.bytesToHexString(clientWriteIv));
        serverWriteIv = Arrays.copyOfRange(keyBlock, offset, offset + saltSize);
        offset += saltSize;
        LOGGER.debug("Server write IV: {}", ArrayConverter.bytesToHexString(serverWriteIv));
    }

    private void initForTLS13(CipherSuite cipherSuite, CipherAlgorithm cipherAlg) {
        if (tlsContext.isUpdateKeys() == false) {
            clientSecret = tlsContext.getClientHandshakeTrafficSecret();
            serverSecret = tlsContext.getServerHandshakeTrafficSecret();
        } else {
            tlsContext.setUpdateKeys(false);
            clientSecret = tlsContext.getClientApplicationTrafficSecret0();
            serverSecret = tlsContext.getServerApplicationTrafficSecret0();
        }
        HKDFAlgorithm hkdfAlgortihm = AlgorithmResolver.getHKDFAlgorithm(cipherSuite);
        clientWriteKey = HKDFunction.expandLabel(hkdfAlgortihm, clientSecret, HKDFunction.KEY, new byte[] {},
                cipherAlg.getKeySize());
        LOGGER.debug("Client write key: {}", ArrayConverter.bytesToHexString(clientWriteKey));
        serverWriteKey = HKDFunction.expandLabel(hkdfAlgortihm, serverSecret, HKDFunction.KEY, new byte[] {},
                cipherAlg.getKeySize());
        LOGGER.debug("Server write key: {}", ArrayConverter.bytesToHexString(serverWriteKey));
        clientWriteIv = HKDFunction.expandLabel(hkdfAlgortihm, clientSecret, HKDFunction.IV, new byte[] {},
                GCM_IV_LENGTH);
        LOGGER.debug("Client write IV: {}", ArrayConverter.bytesToHexString(clientWriteIv));
        serverWriteIv = HKDFunction.expandLabel(hkdfAlgortihm, serverSecret, HKDFunction.IV, new byte[] {},
                GCM_IV_LENGTH);
        LOGGER.debug("Server write IV: {}", ArrayConverter.bytesToHexString(serverWriteIv));
    }

    @Override
    public byte[] encrypt(byte[] data) {
        if (tlsContext.getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
            return encryptTLS13(data);
        } else {
            return encryptTLS12(data);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        if (tlsContext.getSelectedProtocolVersion() == ProtocolVersion.TLS13) {
            return decryptTLS13(data);
        } else {
            return decryptTLS12(data);
        }
    }

    private byte[] encryptTLS13(byte[] data) {
        try {
            byte[] sequenceNumberByte = ArrayConverter.longToBytes(tlsContext.getWriteSequenceNumber(),
                    RecordByteLength.SEQUENCE_NUMBER);
            byte[] nonce = ArrayConverter.concatenate(new byte[GCM_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                    sequenceNumberByte);
            if (tlsContext.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
                encryptIV = prepareGCMParameters(nonce, clientWriteIv);
            } else {
                encryptIV = prepareGCMParameters(nonce, serverWriteIv);
            }
            LOGGER.debug("Encrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(encryptIV.getIV()));
            encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIV);
            return encryptCipher.doFinal(data);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    private GCMParameterSpec prepareGCMParameters(byte[] nonce, byte[] writeIv) {
        byte[] param = new byte[GCM_IV_LENGTH];
        for (int i = 0; i < GCM_IV_LENGTH; i++) {
            param[i] = (byte) (writeIv[i] ^ nonce[i]);
        }
        return new GCMParameterSpec(GCM_TAG_LENGTH * 8, param);
    }

    private byte[] encryptTLS12(byte[] data) {
        try {
            byte[] nonce = ArrayConverter.longToBytes(tlsContext.getWriteSequenceNumber(),
                    RecordByteLength.SEQUENCE_NUMBER);
            if (tlsContext.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
                byte[] iv = ArrayConverter.concatenate(clientWriteIv, nonce);
                encryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            } else {
                byte[] iv = ArrayConverter.concatenate(serverWriteIv, nonce);
                encryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            }
            LOGGER.debug("Encrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(encryptIV.getIV()));
            encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIV);
            LOGGER.debug("Encrypting GCM with the following AAD: {}", ArrayConverter.bytesToHexString(aad));
            encryptCipher.updateAAD(aad);
            byte[] ciphertext = encryptCipher.doFinal(data);
            return ArrayConverter.concatenate(nonce, ciphertext);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    private byte[] decryptTLS13(byte[] data) {
        try {
            byte[] sequenceNumberByte = ArrayConverter.longToBytes(tlsContext.getReadSequenceNumber(),
                    RecordByteLength.SEQUENCE_NUMBER);
            byte[] nonce = ArrayConverter.concatenate(new byte[GCM_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                    sequenceNumberByte);
            if (tlsContext.getConfig().getConnectionEndType() == ConnectionEndType.SERVER) {
                decryptIV = prepareGCMParameters(nonce, clientWriteIv);
            } else {
                decryptIV = prepareGCMParameters(nonce, serverWriteIv);
            }
            LOGGER.debug("Decrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(decryptIV.getIV()));
            decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey, decryptIV);
            LOGGER.debug("Decrypting the following GCM ciphertext: {}", ArrayConverter.bytesToHexString(data));
            return decryptCipher.doFinal(data);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    private byte[] decryptTLS12(byte[] data) {
        try {
            byte[] nonce = Arrays.copyOf(data, SEQUENCE_NUMBER_LENGTH);
            data = Arrays.copyOfRange(data, SEQUENCE_NUMBER_LENGTH, data.length);
            if (tlsContext.getConfig().getConnectionEndType() == ConnectionEndType.SERVER) {
                byte[] iv = ArrayConverter.concatenate(clientWriteIv, nonce);
                decryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            } else {
                byte[] iv = ArrayConverter.concatenate(serverWriteIv, nonce);
                decryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            }
            LOGGER.debug("Decrypting GCM with the following IV: {}", ArrayConverter.bytesToHexString(decryptIV.getIV()));
            decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey, decryptIV);
            LOGGER.debug("Decrypting GCM with the following AAD: {}", ArrayConverter.bytesToHexString(aad));
            decryptCipher.updateAAD(aad);
            LOGGER.debug("Decrypting the following GCM ciphertext: {}", ArrayConverter.bytesToHexString(data));
            return decryptCipher.doFinal(data);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    @Override
    public boolean isUsingPadding() {
        return false;
    }

    @Override
    public boolean isUsingMac() {
        return false;
    }

    @Override
    public int getPlainCipherLengthDifference() {
        return SEQUENCE_NUMBER_LENGTH + GCM_TAG_LENGTH;
    }

}
