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
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public final class RecordBlockCipher extends RecordCipher {

    /**
     * indicates if explicit IV values should be used (as in TLS 1.1 and higher)
     */
    private boolean useExplicitIv;

    /**
     * cipher for encryption
     */
    private Cipher encryptCipher;

    /**
     * cipher for decryption
     */
    private Cipher decryptCipher;

    /**
     * mac for verification of incoming messages
     */
    private Mac readMac;

    /**
     * mac object for macing outgoing messages
     */
    private Mac writeMac;

    /**
     * encryption IV
     */
    private IvParameterSpec encryptIv;

    /**
     * decryption IV
     */
    private IvParameterSpec decryptIv;

    /**
     * CipherAlgorithm algorithm (AES, 3DES ...)
     */
    private BulkCipherAlgorithm bulkCipherAlg;

    /**
     * client encryption key
     */
    private byte[] clientWriteKey;

    /**
     * server encryption key
     */
    private byte[] serverWriteKey;

    private SecretKey encryptKey;

    private SecretKey decryptKey;

    /**
     * TLS context
     */
    private final TlsContext tlsContext;

    public RecordBlockCipher(TlsContext tlsContext) {
        super(0, true, true);
        this.tlsContext = tlsContext;
        init();
    }

    /**
     * From the Lucky13 paper: An individual record R (viewed as a byte sequence
     * of length at least zero) is processed as follows. The sender maintains an
     * 8-byte sequence number SQN which is incremented for each record sent, and
     * forms a 5-byte field HDR consisting of a 1-byte type field, a 2-byte
     * version field, and a 2-byte length field. It then calculates a MAC over
     * the bytes SQN || HDR || R.
     *
     * @param data
     * @return
     */
    @Override
    public byte[] calculateMac(byte[] data) {
        writeMac.update(data);
        LOGGER.debug("The MAC was caluculated over the following data: {}", ArrayConverter.bytesToHexString(data));
        byte[] result = writeMac.doFinal();
        LOGGER.debug("MAC result: {}", ArrayConverter.bytesToHexString(result));
        return result;
    }

    /**
     * Takes correctly padded data and encrypts it
     *
     * @param data
     *            correctly padded data
     * @return
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(byte[] data) throws CryptoException {
        try {
            byte[] ciphertext;
            if (useExplicitIv) {
                ciphertext = ArrayConverter.concatenate(encryptIv.getIV(), encryptCipher.doFinal(data));
            } else {
                encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIv);
                ciphertext = encryptCipher.doFinal(data);
                encryptIv = new IvParameterSpec(Arrays.copyOfRange(ciphertext,
                        ciphertext.length - decryptCipher.getBlockSize(), ciphertext.length));
            }
            return ciphertext;
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException
                | InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }

    /**
     * Takes ciphertexts and decrypts it
     *
     * @param data
     *            correctly padded data
     * @return
     * @throws CryptoException
     */
    @Override
    public byte[] decrypt(byte[] data) throws CryptoException {
        try {
            byte[] plaintext;
            if (useExplicitIv) {
                decryptIv = new IvParameterSpec(Arrays.copyOf(data, decryptCipher.getBlockSize()));
            }
            if (tlsContext.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
                decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName()),
                        decryptIv);
            } else {
                decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName()),
                        decryptIv);
            }
            if (useExplicitIv) {
                plaintext = decryptCipher.doFinal(Arrays.copyOfRange(data, decryptCipher.getBlockSize(), data.length));
            } else {
                plaintext = decryptCipher.doFinal(data);
                decryptIv = new IvParameterSpec(Arrays.copyOfRange(data, data.length - decryptCipher.getBlockSize(),
                        data.length));
            }
            return plaintext;
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException
                | InvalidKeyException | UnsupportedOperationException ex) {
            throw new CryptoException(ex);
        }
    }

    private void init() {
        try {
            ProtocolVersion protocolVersion = tlsContext.getSelectedProtocolVersion();
            CipherSuite cipherSuite = tlsContext.getSelectedCipherSuite();
            if (protocolVersion == ProtocolVersion.TLS11 || protocolVersion == ProtocolVersion.TLS12
                    || protocolVersion == ProtocolVersion.DTLS10 || protocolVersion == ProtocolVersion.DTLS12) {
                useExplicitIv = true;
            }
            bulkCipherAlg = BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherSuite);
            CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
            int keySize = cipherAlg.getKeySize();
            encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(cipherSuite);
            readMac = Mac.getInstance(macAlg.getJavaName());
            writeMac = Mac.getInstance(macAlg.getJavaName());
            int secretSetSize = (2 * keySize) + readMac.getMacLength() + writeMac.getMacLength();
            if (!useExplicitIv) {
                secretSetSize += encryptCipher.getBlockSize() + decryptCipher.getBlockSize();
            }
            byte[] masterSecret = tlsContext.getMasterSecret();
            byte[] seed = ArrayConverter.concatenate(tlsContext.getServerRandom(), tlsContext.getClientRandom());

            PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(protocolVersion, cipherSuite);
            byte[] keyBlock = PseudoRandomFunction.compute(prfAlgorithm, masterSecret,
                    PseudoRandomFunction.KEY_EXPANSION_LABEL, seed, secretSetSize);
            LOGGER.debug("A new key block was generated: {}", ArrayConverter.bytesToHexString(keyBlock));
            int offset = 0;
            byte[] clientMacWriteSecret = Arrays.copyOfRange(keyBlock, offset, offset + readMac.getMacLength());
            offset += readMac.getMacLength();
            LOGGER.debug("Client MAC write Secret: {}", ArrayConverter.bytesToHexString(clientMacWriteSecret));
            byte[] serverMacWriteSecret = Arrays.copyOfRange(keyBlock, offset, offset + writeMac.getMacLength());
            offset += writeMac.getMacLength();
            LOGGER.debug("Server MAC write Secret:  {}", ArrayConverter.bytesToHexString(serverMacWriteSecret));
            clientWriteKey = Arrays.copyOfRange(keyBlock, offset, offset + keySize);
            offset += keySize;
            LOGGER.debug("Client write key: {}", ArrayConverter.bytesToHexString(clientWriteKey));
            serverWriteKey = Arrays.copyOfRange(keyBlock, offset, offset + keySize);
            offset += keySize;
            LOGGER.debug("Server write key: {}", ArrayConverter.bytesToHexString(serverWriteKey));
            byte[] clientWriteIv, serverWriteIv;
            if (useExplicitIv) {
                clientWriteIv = new byte[encryptCipher.getBlockSize()];
                RandomHelper.getRandom().nextBytes(clientWriteIv);
                serverWriteIv = new byte[decryptCipher.getBlockSize()];
                RandomHelper.getRandom().nextBytes(serverWriteIv);
            } else {
                clientWriteIv = Arrays.copyOfRange(keyBlock, offset, offset + encryptCipher.getBlockSize());
                offset += encryptCipher.getBlockSize();
                LOGGER.debug("Client write IV: {}", ArrayConverter.bytesToHexString(clientWriteIv));
                serverWriteIv = Arrays.copyOfRange(keyBlock, offset, offset + decryptCipher.getBlockSize());
                offset += decryptCipher.getBlockSize();
                LOGGER.debug("Server write IV: {}", ArrayConverter.bytesToHexString(serverWriteIv));
            }
            if (tlsContext.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
                encryptIv = new IvParameterSpec(clientWriteIv);
                decryptIv = new IvParameterSpec(serverWriteIv);
                encryptKey = new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName());
                decryptKey = new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName());
                try {
                    encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIv);
                    decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey, decryptIv);
                    readMac.init(new SecretKeySpec(serverMacWriteSecret, macAlg.getJavaName()));
                    writeMac.init(new SecretKeySpec(clientMacWriteSecret, macAlg.getJavaName()));
                } catch (InvalidAlgorithmParameterException | InvalidKeyException E) {
                    throw new UnsupportedOperationException("Unsupported Ciphersuite:"
                            + tlsContext.getSelectedCipherSuite().name(), E);
                }
            } else {
                decryptIv = new IvParameterSpec(clientWriteIv);
                encryptIv = new IvParameterSpec(serverWriteIv);
                decryptKey = new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName());
                encryptKey = new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName());
                try {
                    encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIv);
                    decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey, decryptIv);
                    readMac.init(new SecretKeySpec(clientMacWriteSecret, macAlg.getJavaName()));
                    writeMac.init(new SecretKeySpec(serverMacWriteSecret, macAlg.getJavaName()));
                } catch (InvalidAlgorithmParameterException | InvalidKeyException E) {
                    throw new UnsupportedOperationException("Unsupported Ciphersuite:"
                            + tlsContext.getSelectedCipherSuite().name(), E);
                }
            }
            if (offset != keyBlock.length) {
                throw new CryptoException("Offset exceeded the generated key block length");
            } // mac has to be put into one or more blocks, depending on the
              // MAC/block
              // length
              // additionally, there is a need for one explicit IV block
            setMinimalEncryptedRecordLength(((readMac.getMacLength() / decryptCipher.getBlockSize()) + 2)
                    * decryptCipher.getBlockSize());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new CryptoException("Could not initialize RecordBlocKCipher with Ciphersuite:"
                    + tlsContext.getSelectedCipherSuite().name(), ex);
        }
    }

    @Override
    public int getMacLength() {
        return readMac.getMacLength();
    }

    @Override
    public byte[] calculatePadding(int paddingLength) {
        paddingLength = Math.abs(paddingLength); // TODO why?!
        byte[] padding = new byte[paddingLength];
        for (int i = 0; i < paddingLength; i++) {
            padding[i] = (byte) (paddingLength - 1);
        }
        return padding;
    }

    @Override
    public int getPaddingLength(int dataLength) {
        return encryptCipher.getBlockSize() - (dataLength % encryptCipher.getBlockSize());
    }
}
