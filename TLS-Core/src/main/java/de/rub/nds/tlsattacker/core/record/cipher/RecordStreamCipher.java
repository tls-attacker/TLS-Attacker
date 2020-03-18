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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.MacWrapper;
import de.rub.nds.tlsattacker.core.crypto.mac.WrappedMac;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.RecordCryptoComputations;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cryptomator.siv.org.bouncycastle.util.Arrays;

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
    public void encrypt(Record record) throws CryptoException {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not prepared.");
            record.prepareComputations();
        }
        LOGGER.debug("Encrypting Record:");
        RecordCryptoComputations computations = record.getComputations();

        record.getComputations().setMacKey(getKeySet().getWriteMacSecret(context.getChooser().getConnectionEndType()));
        record.getComputations().setCipherKey(getKeySet().getWriteKey(context.getChooser().getConnectionEndType()));

        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();

        computations.setAuthenticatedNonMetaData(cleanBytes);

        computations.setMac(calculateMac(ArrayConverter.concatenate(
                collectAdditionalAuthenticatedData(record, version), cleanBytes), context.getConnection()
                .getLocalConnectionEndType()));

        record.getComputations().setPlainRecordBytes(record.getCleanProtocolMessageBytes().getValue());

        computations.setCiphertext(encryptCipher.encrypt(record.getComputations().getPlainRecordBytes().getValue()));

        record.setProtocolMessageBytes(Arrays.concatenate(computations.getCiphertext().getValue(), computations
                .getMac().getValue()));

    }

    @Override
    public void decrypt(Record record) throws CryptoException {
        if (record.getComputations() == null) {
            LOGGER.warn("Record computations are not preapred.");
            record.prepareComputations();
        }
        LOGGER.debug("Decrypting Record");
        RecordCryptoComputations computations = record.getComputations();

        computations.setMacKey(getKeySet().getReadMacSecret(context.getChooser().getConnectionEndType()));
        computations.setCipherKey(getKeySet().getReadKey(context.getChooser().getConnectionEndType()));

        byte[] plaintext = record.getProtocolMessageBytes().getValue();
        DecryptionParser parser = new DecryptionParser(0, plaintext);
        CipherSuite cipherSuite = context.getChooser().getSelectedCipherSuite();

        byte[] ciphertext = parser.parseByteArrayField(plaintext.length - readMac.getMacLength());
        byte[] plainData = decryptCipher.decrypt(ciphertext);

        computations.setPlainRecordBytes(plainData);
        plainData = computations.getPlainRecordBytes().getValue();

        byte[] cleanProtocolBytes = computations.getPlainRecordBytes().getValue();
        record.setCleanProtocolMessageBytes(cleanProtocolBytes);

        byte[] hmac = parser.parseByteArrayField(readMac.getMacLength());
        record.getComputations().setMac(hmac);
    }

    @Override
    public void encrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Encrypting BlobRecord");
        br.setProtocolMessageBytes(encryptCipher.encrypt(br.getCleanProtocolMessageBytes().getValue()));
    }

    @Override
    public void decrypt(BlobRecord br) throws CryptoException {
        LOGGER.debug("Derypting BlobRecord");
        br.setProtocolMessageBytes(decryptCipher.decrypt(br.getCleanProtocolMessageBytes().getValue()));
    }

    class DecryptionParser extends Parser<Object> {

        public DecryptionParser(int startposition, byte[] array) {
            super(startposition, array);
        }

        @Override
        public Object parse() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] parseByteArrayField(int length) {
            return super.parseByteArrayField(length);
        }

        @Override
        public int getBytesLeft() {
            return super.getBytesLeft();
        }

        @Override
        public int getPointer() {
            return super.getPointer();
        }

    }
}
