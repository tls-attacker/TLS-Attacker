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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
     * client secret
     */
    private byte[] clientSecret;

    /**
     * server secret
     */
    private byte[] serverSecret;

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
        ProtocolVersion protocolVersion = context.getChooser().getSelectedProtocolVersion();
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();
        try {
            bulkCipherAlg = BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherSuite);
            CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
            encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            if (protocolVersion.isTLS13()) {
                if (context.isUpdateKeys() == false) {
                    if(context.isUseEarlyTrafficSecret()) {
                        context.setUseEarlyTrafficSecret(false);
                        clientSecret = context.getClientEarlyTrafficSecret();
                        serverSecret = context.getClientEarlyTrafficSecret(); //Just to avoid errors
                    }
                    else {
                        clientSecret = context.getClientHandshakeTrafficSecret();
                        serverSecret = context.getServerHandshakeTrafficSecret(); 
                    }
                } else {
                    context.setUpdateKeys(false);
                    clientSecret = context.getClientApplicationTrafficSecret0();
                    serverSecret = context.getServerApplicationTrafficSecret0();
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
                if (context.getChooser().getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT) {
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
            byte[] sequenceNumberByte = ArrayConverter.longToBytes(sequenceNumberEnc, RecordByteLength.SEQUENCE_NUMBER);
            byte[] nonce = ArrayConverter.concatenate(new byte[GCM_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                    sequenceNumberByte);
            if (context.getChooser().getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT) {
                byte[] newClientWriteIv = new byte[GCM_IV_LENGTH];
                for (int i = 0; i < GCM_IV_LENGTH; i++) {
                    newClientWriteIv[i] = (byte) (clientWriteIv[i] ^ nonce[i]);
                }
                encryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, newClientWriteIv);
            } else {
                byte[] newServerWriteIv = new byte[GCM_IV_LENGTH];
                for (int i = 0; i < GCM_IV_LENGTH; i++) {
                    newServerWriteIv[i] = (byte) (serverWriteIv[i] ^ nonce[i]);
                }
                encryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, newServerWriteIv);

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
            byte[] sequenceNumberByte = ArrayConverter.longToBytes(sequenceNumberDec, RecordByteLength.SEQUENCE_NUMBER);
            byte[] nonce = ArrayConverter.concatenate(new byte[GCM_IV_LENGTH - RecordByteLength.SEQUENCE_NUMBER],
                    sequenceNumberByte);
            if (context.getChooser().getConnectionEnd().getConnectionEndType() == ConnectionEndType.SERVER) {
                byte[] newClientWriteIv = new byte[GCM_IV_LENGTH];
                for (int i = 0; i < GCM_IV_LENGTH; i++) {
                    newClientWriteIv[i] = (byte) (clientWriteIv[i] ^ nonce[i]);
                }
                decryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, newClientWriteIv);
            } else {
                byte[] newServerWriteIv = new byte[GCM_IV_LENGTH];
                for (int i = 0; i < GCM_IV_LENGTH; i++) {
                    newServerWriteIv[i] = (byte) (serverWriteIv[i] ^ nonce[i]);
                }
                decryptIV = new GCMParameterSpec(GCM_TAG_LENGTH * 8, newServerWriteIv);
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
        return 0;
    }

    @Override
    public byte[] calculateMac(byte[] data) {
        return new byte[] {};
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

    public void setSequenceNumberEnc(long sequenceNumberEnc)
    {
        this.sequenceNumberEnc = sequenceNumberEnc;
    }
    
    public long getSequenceNumberEnc()
    {
        return sequenceNumberEnc;
    }
    
    public long getSequenceNumberDec()
    {
        return sequenceNumberDec;
    }
    
    public void setSequenceNumberDec(long sequenceNumberDec)
    {
        this.sequenceNumberDec = sequenceNumberDec;
    }
}
