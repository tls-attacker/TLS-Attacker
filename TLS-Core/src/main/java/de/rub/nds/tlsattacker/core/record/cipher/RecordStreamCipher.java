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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordStreamCipher extends RecordCipher {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * mac for verification of incoming messages
     */
    private WrappedMac readMac;
    /**
     * mac object for macing outgoing messages
     */
    private WrappedMac writeMac;

    public RecordStreamCipher(TlsContext context, KeySet keySet) {
        super(context, keySet);
        initCipherAndMac();
    }

    private void initCipherAndMac() throws UnsupportedOperationException {
        try {
            ConnectionEndType localConEndType = context.getConnection().getLocalConnectionEndType();
            encryptCipher = CipherWrapper.getEncryptionCipher(cipherSuite, localConEndType, getKeySet());
            decryptCipher = CipherWrapper.getDecryptionCipher(cipherSuite, localConEndType, getKeySet());
            readMac = MacWrapper.getMac(version, cipherSuite, getKeySet().getReadMacSecret(localConEndType));
            writeMac = MacWrapper.getMac(version, cipherSuite, getKeySet().getWriteMacSecret(localConEndType));
        } catch (NoSuchAlgorithmException ex) {
            throw new UnsupportedOperationException("Cipher not supported: " + cipherSuite.name(), ex);
        }
    }

    @Override
    public EncryptionResult encrypt(EncryptionRequest request) {
        try {
            return new EncryptionResult(encryptCipher.encrypt(request.getPlainText()));
        } catch (CryptoException E) {
            LOGGER.warn("Could not encrypt Data with the provided parameters. Returning unencrypted data.");
            LOGGER.debug(E);
            return new EncryptionResult(request.getPlainText());
        }
    }

    @Override
    public DecryptionResult decrypt(DecryptionRequest decryptionRequest) {
        try {
            return new DecryptionResult(null, decryptCipher.decrypt(decryptionRequest.getCipherText()), null, true);
        } catch (CryptoException E) {
            LOGGER.warn("Could not decrypt Data with the provided parameters. Returning undecrypted data.");
            LOGGER.debug(E);
            return new DecryptionResult(null, decryptionRequest.getCipherText(), false, false);
        }
    }

    @Override
    public int getMacLength() {
        return readMac.getMacLength();
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

    @Override
    public byte[] calculatePadding(int paddingLength) {
        return new byte[0];
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
