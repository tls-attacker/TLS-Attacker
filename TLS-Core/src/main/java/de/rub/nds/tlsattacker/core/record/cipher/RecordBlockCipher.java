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
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.MacWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class RecordBlockCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * indicates if explicit IV values should be used (as in TLS 1.1 and higher)
     */
    private boolean useExplicitIv;
    /**
     * mac for verification of incoming messages
     */
    private WrappedMac readMac;
    /**
     * mac object for macing outgoing messages
     */
    private WrappedMac writeMac;

    public RecordBlockCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        if (version.usesExplicitIv()) {
            useExplicitIv = true;
        }
        ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();

        try {
            encryptCipher = CipherWrapper.getEncryptionCipher(cipherSuite, localConEndType, getKeySet());
            decryptCipher = CipherWrapper.getDecryptionCipher(cipherSuite, localConEndType, getKeySet());
            readMac = MacWrapper.getMac(version, cipherSuite, getKeySet().getReadMacSecret(localConEndType));
            writeMac = MacWrapper.getMac(version, cipherSuite, getKeySet().getWriteMacSecret(localConEndType));
        } catch (NoSuchAlgorithmException E) {
            throw new UnsupportedOperationException("Unsupported Ciphersuite:" + cipherSuite.name(), E);
        }
    }

    @Override
    public byte[] calculateMac(byte[] data, ConnectionEndType connectionEndType) {
        LOGGER.debug("The MAC was calculated over the following data: {}", ArrayConverter.bytesToHexString(data));
        byte[] result;
        if (connectionEndType == context.getChooser().getConnectionEndType()) {
            result = writeMac.calculateMac(data);
        } else {
            result = readMac.calculateMac(data);
        }
        LOGGER.debug("MAC: {}", ArrayConverter.bytesToHexString(result));
        return result;
    }

    /**
     * Takes correctly padded data and encrypts it
     *
     * @param request
     *            The RequestedEncryption operation
     * @return The EncryptionResult
     */
    @Override
    public EncryptionResult encrypt(EncryptionRequest request) {
        try {
            byte[] expandedPlaintext = this.expandToBlocksize(request.getPlainText());
            byte[] ciphertext = encryptCipher.encrypt(request.getInitialisationVector(), expandedPlaintext);
            if (!useExplicitIv) {
                encryptCipher.setIv(extractNextEncryptIv(ciphertext));
            }
            LOGGER.debug("EncryptIv: " + ArrayConverter.bytesToHexString(encryptCipher.getIv()));
            return new EncryptionResult(encryptCipher.getIv(), ciphertext, useExplicitIv);

        } catch (CryptoException ex) {
            LOGGER.warn("Could not encrypt Data with the provided parameters. Returning unencrypted data.", ex);
            return new EncryptionResult(request.getPlainText());
        }
    }

    private byte[] extractNextEncryptIv(byte[] ciphertext) {
        return Arrays.copyOfRange(ciphertext, ciphertext.length - encryptCipher.getBlocksize(), ciphertext.length);
    }

    private byte[] expandToBlocksize(byte[] plaintext) {
        byte[] expandedPlaintext = plaintext;
        int blocksize = this.encryptCipher.getBlocksize();
        if (plaintext != null && blocksize > 0 && (plaintext.length % blocksize) != 0) {
            int numberOfBlocks = (plaintext.length / blocksize) + 1;
            expandedPlaintext = new byte[numberOfBlocks * blocksize];
            System.arraycopy(plaintext, 0, expandedPlaintext, 0, plaintext.length);
        }
        return expandedPlaintext;
    }

    /**
     * Takes a ciphertext and decrypts it
     *
     * @param decryptionRequest
     * @return The raw decrypted Bytes
     */
    @Override
    public DecryptionResult decrypt(DecryptionRequest decryptionRequest) {
        try {
            byte[] plaintext;
            byte[] usedIv;
            if (decryptionRequest.getCipherText().length % decryptCipher.getBlocksize() != 0) {
                LOGGER.warn("Ciphertext is not a multiple of the Blocksize. Not Decrypting");
                return new DecryptionResult(new byte[0], decryptionRequest.getCipherText(), useExplicitIv, false);
            }
            if (useExplicitIv) {
                byte[] decryptIv = Arrays.copyOf(decryptionRequest.getCipherText(), decryptCipher.getBlocksize());
                LOGGER.debug("decryptionIV: " + ArrayConverter.bytesToHexString(decryptIv));
                plaintext = decryptCipher.decrypt(decryptIv, Arrays.copyOfRange(decryptionRequest.getCipherText(),
                        decryptCipher.getBlocksize(), decryptionRequest.getCipherText().length));
                usedIv = decryptIv;
            } else {
                byte[] decryptIv = getDecryptionIV();
                LOGGER.debug("decryptionIV: " + ArrayConverter.bytesToHexString(decryptIv));
                plaintext = decryptCipher.decrypt(decryptIv, decryptionRequest.getCipherText());
                usedIv = decryptIv;
                // Set next IV
            }

            return new DecryptionResult(usedIv, plaintext, useExplicitIv, true);
        } catch (CryptoException | UnsupportedOperationException ex) {
            LOGGER.warn("Could not decrypt Data with the provided parameters. Returning undecrypted data.", ex);
            return new DecryptionResult(null, decryptionRequest.getCipherText(), useExplicitIv, false);
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
    public int calculatePaddingLength(int dataLength) {
        return encryptCipher.getBlocksize() - (dataLength % encryptCipher.getBlocksize());
    }

    @Override
    public boolean isUsingPadding() {
        return true;
    }

    @Override
    public boolean isUsingMac() {
        return true;
    }

    @Override
    public boolean isUsingTags() {
        return false;
    }

    @Override
    public byte[] getEncryptionIV() {
        if (useExplicitIv) {
            CipherAlgorithm cipherAlgorithm = AlgorithmResolver.getCipher(cipherSuite);
            byte[] iv = new byte[cipherAlgorithm.getNonceBytesFromHandshake()];
            context.getRandom().nextBytes(iv);
            return iv;
        } else {
            byte[] tempIv = encryptCipher.getIv();
            if (tempIv == null) {
                ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
                return getKeySet().getWriteIv(localConEndType);
            } else {
                return tempIv;
            }
        }
    }

    @Override
    public byte[] getDecryptionIV() {
        if (useExplicitIv) {
            return new byte[0];
        } else {
            byte[] tempIv = decryptCipher.getIv();
            if (tempIv == null) {
                ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
                return getKeySet().getReadIv(localConEndType);
            } else {
                return tempIv;
            }
        }
    }
}
