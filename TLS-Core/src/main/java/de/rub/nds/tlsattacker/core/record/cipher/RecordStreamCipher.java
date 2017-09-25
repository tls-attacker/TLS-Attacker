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
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import static de.rub.nds.tlsattacker.core.record.cipher.RecordCipher.LOGGER;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RecordStreamCipher extends RecordCipher {

    private final TlsContext tlsContext;

    /**
     * mac for verification of incoming messages
     */
    private Mac readMac;

    /**
     * mac object for macing outgoing messages
     */
    private Mac writeMac;

    /**
     * CipherAlgorithm algorithm (AES, 3DES ...)
     */
    private BulkCipherAlgorithm bulkCipherAlg;

    /**
     * cipher for encryption
     */
    private Cipher encryptCipher;

    /**
     * cipher for decryption
     */
    private Cipher decryptCipher;

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

    public RecordStreamCipher(TlsContext tlsContext) {
        super(0, false, true);
        this.tlsContext = tlsContext;
        init();
    }

    private void init() {
        try {
            ProtocolVersion protocolVersion = tlsContext.getChooser().getSelectedProtocolVersion();
            CipherSuite cipherSuite = tlsContext.getChooser().getSelectedCipherSuite();
            bulkCipherAlg = BulkCipherAlgorithm.getBulkCipherAlgorithm(cipherSuite);
            CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
            int keySize = cipherAlg.getKeySize();
            encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(cipherSuite);
            readMac = Mac.getInstance(macAlg.getJavaName());
            writeMac = Mac.getInstance(macAlg.getJavaName());
            int secretSetSize = (2 * keySize) + readMac.getMacLength() + writeMac.getMacLength();
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
            if (tlsContext.getChooser().getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT) {
                encryptKey = new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName());
                decryptKey = new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName());
                try {
                    encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey);
                    decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey);
                    readMac.init(new SecretKeySpec(serverMacWriteSecret, macAlg.getJavaName()));
                    writeMac.init(new SecretKeySpec(clientMacWriteSecret, macAlg.getJavaName()));
                } catch (InvalidKeyException E) {
                    throw new UnsupportedOperationException("Unsupported Ciphersuite:"
                            + tlsContext.getChooser().getSelectedCipherSuite().name(), E);
                }
            } else {
                decryptKey = new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName());
                encryptKey = new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName());
                try {
                    encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey);
                    decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey);
                    readMac.init(new SecretKeySpec(clientMacWriteSecret, macAlg.getJavaName()));
                    writeMac.init(new SecretKeySpec(serverMacWriteSecret, macAlg.getJavaName()));
                } catch (InvalidKeyException E) {
                    throw new UnsupportedOperationException("Unsupported Ciphersuite:"
                            + tlsContext.getChooser().getSelectedCipherSuite().name(), E);
                }
            }
            if (offset != keyBlock.length) {
                throw new CryptoException("Offset exceeded the generated key block length");
            }
            setMinimalEncryptedRecordLength(readMac.getMacLength());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new CryptoException("Could not initialize StreamCipher with Ciphersuite:"
                    + tlsContext.getChooser().getSelectedCipherSuite().name(), ex);
        }
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return encryptCipher.update(data);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return decryptCipher.update(data);
    }

    @Override
    public int getMacLength() {
        return readMac.getMacLength();
    }

    @Override
    public byte[] calculateMac(byte[] data) {
        writeMac.update(data);
        LOGGER.debug("The MAC was caluculated over the following data: {}", ArrayConverter.bytesToHexString(data));
        byte[] result = writeMac.doFinal();
        LOGGER.debug("MAC result: {}", ArrayConverter.bytesToHexString(result));
        return result;
    }

    @Override
    public byte[] calculatePadding(int paddingLength) {
        return new byte[] {};
    }

    @Override
    public int getPaddingLength(int dataLength) {
        return 0;
    }
}
