/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.layer;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.compressor.RecordDecompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Decryptor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordEncryptor;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class RecordLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext tlsContext;

    private final Decryptor decryptor;
    private final Encryptor encryptor;

    private final RecordCompressor compressor;
    private final RecordDecompressor decompressor;

    private int writeEpoch = 0;
    private int readEpoch = 0;

    public RecordLayer(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
        encryptor = new RecordEncryptor(RecordCipherFactory.getNullCipher(tlsContext), tlsContext);
        decryptor = new RecordDecryptor(RecordCipherFactory.getNullCipher(tlsContext), tlsContext);
        compressor = new RecordCompressor(tlsContext);
        decompressor = new RecordDecompressor(tlsContext);
    }

    /**
     * Tries to parse rawBytes into AbstractRecords. If this is not possible a Parser Exception is thrown
     *
     * @param  rawBytes
     *                  Bytes to parse
     * @return          List of parsed records
     */
    public abstract List<AbstractRecord> parseRecords(byte[] rawBytes) throws ParserException;

    /**
     * Tries to parse rawBytes into AbstractRecords. Exceptions which might occur are handled.
     *
     * @param  rawBytes
     *                  Bytes to parse
     * @return          List of parsed records
     */
    public abstract List<AbstractRecord> parseRecordsSoftly(byte[] rawBytes);

    public abstract void decryptAndDecompressRecord(AbstractRecord records);

    public abstract byte[] prepareRecords(byte[] data, ProtocolMessageType contentType, List<AbstractRecord> records);

    public abstract byte[] reencrypt(List<AbstractRecord> records);

    public abstract AbstractRecord getFreshRecord();

    public void updateCompressor() {
        compressor.setMethod(tlsContext.getChooser().getSelectedCompressionMethod());
    }

    public void updateDecompressor() {
        decompressor.setMethod(tlsContext.getChooser().getSelectedCompressionMethod());
    }

    public void updateEncryptionCipher(RecordCipher encryptionCipher) {
        LOGGER.debug("Activating new EncryptionCipher (" + encryptionCipher.getClass().getSimpleName() + ")");
        encryptor.addNewRecordCipher(encryptionCipher);
        writeEpoch++;
    }

    public void updateDecryptionCipher(RecordCipher decryptionCipher) {
        LOGGER.debug("Activating new DecryptionCipher (" + decryptionCipher.getClass().getSimpleName() + ")");
        decryptor.addNewRecordCipher(decryptionCipher);
        readEpoch++;
    }

    public RecordCipher getEncryptorCipher() {
        return encryptor.getRecordMostRecentCipher();
    }

    public RecordCipher getDecryptorCipher() {
        return decryptor.getRecordMostRecentCipher();
    }

    public void resetEncryptor() {
        encryptor.removeAllCiphers();
    }

    public void resetDecryptor() {
        decryptor.removeAllCiphers();
    }

    public Encryptor getEncryptor() {
        return encryptor;
    }

    public Decryptor getDecryptor() {
        return decryptor;
    }

    public RecordCompressor getCompressor() {
        return compressor;
    }

    public RecordDecompressor getDecompressor() {
        return decompressor;
    }

    public TlsContext getTlsContext() {
        return tlsContext;
    }

    public void increaseWriteEpoch() {
        writeEpoch++;
    }

    public int getWriteEpoch() {
        return writeEpoch;
    }

    public void setWriteEpoch(int writeEpoch) {
        this.writeEpoch = writeEpoch;
    }

    public void increaseReadEpoch() {
        readEpoch++;
    }

    public int getReadEpoch() {
        return readEpoch;
    }

    public void setReadEpoch(int readEpoch) {
        this.readEpoch = readEpoch;
    }
}
