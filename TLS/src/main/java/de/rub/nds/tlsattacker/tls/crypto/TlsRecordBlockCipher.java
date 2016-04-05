/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.crypto;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.tls.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class TlsRecordBlockCipher extends TlsRecordCipher {

    private static final Logger LOGGER = LogManager.getLogger(TlsRecordBlockCipher.class);

    /**
     * indicates if explicit IV values should be used (as in TLS 1.1 and higher)
     */
    private boolean useExplicitIv;

    /**
     * cipher for encryption
     */
    private final Cipher encryptCipher;

    /**
     * cipher for decryption
     */
    private final Cipher decryptCipher;

    /**
     * mac for verification of incoming messages
     */
    private final Mac readMac;

    /**
     * mac object for macing outgoing messages
     */
    private final Mac writeMac;

    /**
     * encryption IV
     */
    private IvParameterSpec encryptIv;

    /**
     * decryption IV
     */
    private IvParameterSpec decryptIv;

    /**
     * sequence number used for mac computation
     */
    private long sequenceNumber;

    /**
     * CipherAlgorithm algorithm (AES, 3DES ...)
     */
    private final BulkCipherAlgorithm bulkCipherAlg;

    /**
     * client encryption key
     */
    private final byte[] clientWriteKey;

    /**
     * server encryption key
     */
    private final byte[] serverWriteKey;

    private SecretKey encryptKey;

    private SecretKey decryptKey;

    /**
     * TLS context
     */
    private final TlsContext tlsContext;

    public TlsRecordBlockCipher(TlsContext tlsContext) throws NoSuchAlgorithmException, NoSuchPaddingException,
	    InvalidKeyException, InvalidAlgorithmParameterException {
	this.tlsContext = tlsContext;
	ProtocolVersion protocolVersion = tlsContext.getProtocolVersion();
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
	byte[] seed = tlsContext.getServerClientRandom();

	PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getProtocolVersion(),
		tlsContext.getSelectedCipherSuite());
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

	if (tlsContext.getMyConnectionEnd() == ConnectionEnd.CLIENT) {
	    encryptIv = new IvParameterSpec(clientWriteIv);
	    decryptIv = new IvParameterSpec(serverWriteIv);
	    encryptKey = new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName());
	    decryptKey = new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName());
	    encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey, encryptIv);
	    decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey, decryptIv);
	    readMac.init(new SecretKeySpec(serverMacWriteSecret, macAlg.getJavaName()));
	    writeMac.init(new SecretKeySpec(clientMacWriteSecret, macAlg.getJavaName()));
	} else {
	    decryptIv = new IvParameterSpec(clientWriteIv);
	    encryptIv = new IvParameterSpec(serverWriteIv);
	    // todo check if this correct???
	    encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(serverWriteKey, bulkCipherAlg.getJavaName()),
		    encryptIv);
	    decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(clientWriteKey, bulkCipherAlg.getJavaName()),
		    decryptIv);
	    readMac.init(new SecretKeySpec(clientMacWriteSecret, macAlg.getJavaName()));
	    writeMac.init(new SecretKeySpec(serverMacWriteSecret, macAlg.getJavaName()));
	}

	if (offset != keyBlock.length) {
	    throw new CryptoException("Offset exceeded the generated key block length");
	}

	// mac has to be put into one or more blocks, depending on the MAC/block
	// length
	// additionally, there is a need for one explicit IV block
	minimalEncryptedRecordLength = ((readMac.getMacLength() / decryptCipher.getBlockSize()) + 2)
		* decryptCipher.getBlockSize();
    }

    /**
     * From the Lucky13 paper: An individual record R (viewed as a byte sequence
     * of length at least zero) is processed as follows. The sender maintains an
     * 8-byte sequence number SQN which is incremented for each record sent, and
     * forms a 5-byte field HDR consisting of a 1-byte type field, a 2-byte
     * version field, and a 2-byte length field. It then calculates a MAC over
     * the bytes SQN || HDR || R.
     * 
     * @param protocolVersion
     * @param contentType
     * @param data
     * @return
     */
    public byte[] calculateMac(ProtocolVersion protocolVersion, ProtocolMessageType contentType, byte[] data) {

	byte[] SQN = ArrayConverter.longToUint64Bytes(sequenceNumber);
	byte[] HDR = ArrayConverter.concatenate(contentType.getArrayValue(), protocolVersion.getValue(),
		ArrayConverter.intToBytes(data.length, 2));

	writeMac.update(SQN);
	writeMac.update(HDR);
	writeMac.update(data);

	LOGGER.debug("The MAC was caluculated over the following data: {}",
		ArrayConverter.bytesToHexString(ArrayConverter.concatenate(SQN, HDR, data)));

	byte[] result = writeMac.doFinal();

	LOGGER.debug("MAC result: {}", ArrayConverter.bytesToHexString(result));

	// we increment sequence number for the sent records
	sequenceNumber++;

	return result;
    }

    public byte[] calculateDtlsMac(ProtocolVersion protocolVersion, ProtocolMessageType contentType, byte[] data,
	    long dtlsSequenceNumber, int epochNumber) {

	byte[] SQN = ArrayConverter.concatenate(ArrayConverter.intToBytes(epochNumber, 2),
		ArrayConverter.longToUint48Bytes(dtlsSequenceNumber));
	byte[] HDR = ArrayConverter.concatenate(contentType.getArrayValue(), protocolVersion.getValue(),
		ArrayConverter.intToBytes(data.length, 2));

	writeMac.update(SQN);
	writeMac.update(HDR);
	writeMac.update(data);

	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug("The MAC will be caluculated over the following data: {}", ArrayConverter
		    .bytesToHexString(ArrayConverter.concatenate(ArrayConverter.intToBytes(epochNumber, 2),
			    ArrayConverter.longToUint48Bytes(sequenceNumber), HDR, data)));
	}

	byte[] result = writeMac.doFinal();

	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug("MAC result: {}", ArrayConverter.bytesToHexString(result));
	}

	return result;
    }

    /**
     * Calculates padding length for a given dataLength and the initialized
     * block cipher
     * 
     * @param dataLength
     * @return
     */
    public int calculatePaddingLength(int dataLength) {
	return encryptCipher.getBlockSize() - (dataLength % encryptCipher.getBlockSize());
    }

    /**
     * Creates TLS padding of a defined length
     * 
     * @param paddingLength
     * @return
     */
    public byte[] calculatePadding(int paddingLength) {
	byte[] padding = new byte[paddingLength];
	for (int i = 0; i < paddingLength; i++) {
	    padding[i] = (byte) (paddingLength - 1);
	}
	return padding;
    }

    /**
     * Takes correctly padded data and encrypts it
     * 
     * @param data
     *            correctly padded data
     * @return
     * @throws CryptoException
     */
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
    public byte[] decrypt(byte[] data) throws CryptoException {
	try {
	    byte[] plaintext;
	    if (useExplicitIv) {
		decryptIv = new IvParameterSpec(Arrays.copyOf(data, decryptCipher.getBlockSize()));
	    }
	    if (tlsContext.getMyConnectionEnd() == ConnectionEnd.CLIENT) {
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

    @Override
    public void init() {
    }

    public int getMacLength() {
	return readMac.getMacLength();
    }
}
