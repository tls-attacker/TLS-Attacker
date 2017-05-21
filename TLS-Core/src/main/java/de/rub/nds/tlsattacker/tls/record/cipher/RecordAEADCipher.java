/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.cipher;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.crypto.HKDFunction;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import static de.rub.nds.tlsattacker.tls.record.cipher.RecordCipher.LOGGER;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 * @author Nurullah Erinola
 * 
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
     * cipher for encryption
     */
    private Cipher encryptCipher;

    /**
     * cipher for decryption
     */
    private Cipher decryptCipher;

    /**
     * sequence number used for the decryption
     */
    private long sequenceNumberDec = 0;

    /**
     * sequence number used for the encryption
     */
    private long sequenceNumberEnc = 0;

    /**
     * CipherAlgorithm algorithm (AES, ...)
     */
    private BulkCipherAlgorithm bulkCipherAlg;

    /**
     * client encryption key
     */
    private byte[] clientHandshakeTrafficSecret;

    /**
     * server encryption key
     */
    private byte[] serverHandshakeTrafficSecret;

    /**
     * client encryption key
     */
    private byte[] clientWriteKey;

    /**
     * server encryption key
     */
    private byte[] serverWriteKey;

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

    private final TlsContext context;

    public RecordAEADCipher(TlsContext context) {
        super(0, true, false);
        this.context = context;
        init();
    }

    private void init() {
        ProtocolVersion protocolVersion = context.getSelectedProtocolVersion();
        CipherSuite cipherSuite = context.getSelectedCipherSuite();
        try {
            if (protocolVersion == ProtocolVersion.TLS13) {
                bulkCipherAlg = BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherSuite);
                CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
                encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
                decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
                clientHandshakeTrafficSecret = context.getClientHandshakeTrafficSecret();
                serverHandshakeTrafficSecret = context.getServerHandshakeTrafficSecret();
                MacAlgorithm macAlg = AlgorithmResolver.getHKDFAlgorithm(cipherSuite).getMacAlgorithm();
                clientWriteKey = HKDFunction.expandLabel(macAlg.getJavaName(), clientHandshakeTrafficSecret,
                        HKDFunction.KEY, new byte[] {}, cipherAlg.getKeySize());
                LOGGER.debug("Client write key: {}", ArrayConverter.bytesToHexString(clientWriteKey));
                serverWriteKey = HKDFunction.expandLabel(macAlg.getJavaName(), serverHandshakeTrafficSecret,
                        HKDFunction.KEY, new byte[] {}, cipherAlg.getKeySize());
                LOGGER.debug("Server write key: {}", ArrayConverter.bytesToHexString(serverWriteKey));
                clientWriteIv = HKDFunction.expandLabel(macAlg.getJavaName(), clientHandshakeTrafficSecret,
                        HKDFunction.IV, new byte[] {}, GCM_IV_LENGTH);
                LOGGER.debug("Client write IV: {}", ArrayConverter.bytesToHexString(clientWriteIv));
                serverWriteIv = HKDFunction.expandLabel(macAlg.getJavaName(), serverHandshakeTrafficSecret,
                        HKDFunction.IV, new byte[] {}, GCM_IV_LENGTH);
                LOGGER.debug("Server write IV: {}", ArrayConverter.bytesToHexString(serverWriteIv));
                if (context.getConfig().getConnectionEnd() == ConnectionEnd.CLIENT) {
                    encryptKey = new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName());
                    decryptKey = new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName());
                } else {
                    decryptKey = new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName());
                    encryptKey = new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName());
                }
            } else {
                throw new UnsupportedOperationException("Only supported for TLS 1.3");
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new CryptoException("Could not initialize RecordAEADCipher", ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] data) {
        try {
            byte[] nonce = ArrayConverter.longToBytes(sequenceNumberEnc, GCM_IV_LENGTH);
            if (context.getConfig().getConnectionEnd() == ConnectionEnd.CLIENT) {
                for (int i = 0; i < GCM_IV_LENGTH; i++) {
                    clientWriteIv[i] = (byte) (clientWriteIv[i] ^ nonce[i]);
                }
                encryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, clientWriteIv);
            } else {
                for (int i = 0; i < GCM_IV_LENGTH; i++) {
                    serverWriteIv[i] = (byte) (serverWriteIv[i] ^ nonce[i]);
                }
                encryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, serverWriteIv);

            }
            encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIV);
            sequenceNumberEnc++;
            return encryptCipher.doFinal(data);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        try {
            byte[] nonce = ArrayConverter.longToBytes(sequenceNumberDec, GCM_IV_LENGTH);
            if (context.getConfig().getConnectionEnd() == ConnectionEnd.SERVER) {
                for (int i = 0; i < GCM_IV_LENGTH; i++) {
                    clientWriteIv[i] = (byte) (clientWriteIv[i] ^ nonce[i]);
                }
                decryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, clientWriteIv);
            } else {
                for (int i = 0; i < GCM_IV_LENGTH; i++) {
                    serverWriteIv[i] = (byte) (serverWriteIv[i] ^ nonce[i]);
                }
                decryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, serverWriteIv);

            }
            decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey, decryptIV);
            sequenceNumberDec++;
            return decryptCipher.doFinal(data);
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException
                | InvalidAlgorithmParameterException ex) {
            throw new CryptoException(ex);
        }
    }

    @Override
    public int getMacLength() {
        throw new UnsupportedOperationException("Need not a MAC");
    }

    @Override
    public byte[] calculateMac(byte[] data) {
        throw new UnsupportedOperationException("Need not a MAC");
    }

    @Override
    public byte[] calculatePadding(int paddingLength) {
        paddingLength = Math.abs(paddingLength);
        byte[] padding = new byte[paddingLength];
        for (int i = 0; i < paddingLength; i++) {
            padding[i] = (byte) (0);
        }
        return padding;
    }

    @Override
    public int getPaddingLength(int dataLength) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}