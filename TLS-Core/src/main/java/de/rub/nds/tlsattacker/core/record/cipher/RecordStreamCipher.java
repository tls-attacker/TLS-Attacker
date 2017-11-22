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
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionResult;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RecordStreamCipher extends RecordCipher {

    /**
     * mac for verification of incoming messages
     */
    private Mac readMac;
    /**
     * mac object for macing outgoing messages
     */
    private Mac writeMac;

    public RecordStreamCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        initCipherAndMac();
    }

    private void initCipherAndMac() throws UnsupportedOperationException {
        try {
            CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
            encryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            decryptCipher = Cipher.getInstance(cipherAlg.getJavaName());
            MacAlgorithm macAlg = AlgorithmResolver.getMacAlgorithm(context.getChooser().getSelectedProtocolVersion(),
                    cipherSuite);
            readMac = Mac.getInstance(macAlg.getJavaName());
            writeMac = Mac.getInstance(macAlg.getJavaName());
            ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
            SecretKey encryptKey = new SecretKeySpec(getKeySet().getWriteKey(localConEndType),
                    bulkCipherAlg.getJavaName());
            SecretKey decryptKey = new SecretKeySpec(getKeySet().getReadKey(localConEndType),
                    bulkCipherAlg.getJavaName());
            encryptCipher.init(Cipher.ENCRYPT_MODE, encryptKey);
            decryptCipher.init(Cipher.DECRYPT_MODE, decryptKey);
            readMac.init(new SecretKeySpec(getKeySet().getReadMacSecret(localConEndType), readMac.getAlgorithm()));
            writeMac.init(new SecretKeySpec(getKeySet().getWriteMacSecret(localConEndType), writeMac.getAlgorithm()));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            throw new UnsupportedOperationException("Cipher not supported: " + cipherSuite.name(), ex);
        }

    }

    @Override
    public EncryptionResult encrypt(EncryptionRequest request) throws CryptoException {
        return new EncryptionResult(encryptCipher.update(request.getPlainText()));
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
    public int calculatePaddingLength(int dataLength) {
        return 0;
    }

    @Override
    public boolean isUsingPadding() {
        return false;
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
        return new byte[0];
    }

    @Override
    public byte[] getDecryptionIV() {
        return new byte[0];
    }
}
