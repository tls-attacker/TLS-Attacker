/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.layer;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.compressor.RecordDecompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Decryptor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordEncryptor;
import de.rub.nds.tlsattacker.core.record.parser.BlobRecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.AbstractRecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.AbstractRecordSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobRecordLayer extends RecordLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    private final Encryptor encryptor;
    private final Decryptor decryptor;
    private RecordCompressor compressor;
    private RecordDecompressor decompressor;

    public BlobRecordLayer(TlsContext context) {
        this.context = context;
        encryptor = new RecordEncryptor(new RecordNullCipher(context), context);
        decryptor = new RecordDecryptor(new RecordNullCipher(context), context);
        compressor = new RecordCompressor(context);
        decompressor = new RecordDecompressor(context);
    }

    @Override
    public void updateCompressor() {
        compressor.setMethod(context.getChooser().getSelectedCompressionMethod());
    }

    @Override
    public void updateDecompressor() {
        decompressor.setMethod(context.getChooser().getSelectedCompressionMethod());
    }

    @Override
    public List<AbstractRecord> parseRecords(byte[] rawBytes) {
        List<AbstractRecord> list = new LinkedList<>();
        BlobRecordParser parser = new BlobRecordParser(0, rawBytes, context.getChooser().getSelectedProtocolVersion());
        list.add(parser.parse());
        return list;
    }

    @Override
    public List<AbstractRecord> parseRecordsSoftly(byte[] rawBytes) {
        return parseRecords(rawBytes);
    }

    @Override
    public void decryptAndDecompressRecord(AbstractRecord record) {
        decryptor.decrypt(record);
        decompressor.decompress(record);
        context.increaseReadSequenceNumber();
    }

    @Override
    public byte[] prepareRecords(byte[] data, ProtocolMessageType contentType, List<AbstractRecord> records,
        boolean withPrepare) {
        CleanRecordByteSeperator separator =
            new CleanRecordByteSeperator(records, context.getChooser().getOutboundMaxRecordDataSize(), 0, data);
        records = separator.parse();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AbstractRecord record : records) {
            AbstractRecordPreparator preparator =
                record.getRecordPreparator(context.getChooser(), encryptor, compressor, contentType);
            if (withPrepare) {
                preparator.prepare();
                context.increaseWriteSequenceNumber();
            }
            preparator.encrypt();
            AbstractRecordSerializer serializer = record.getRecordSerializer();
            try {
                byte[] recordBytes = serializer.serialize();
                record.setCompleteRecordBytes(recordBytes);
                stream.write(record.getCompleteRecordBytes().getValue());
            } catch (IOException ex) {
                throw new PreparationException("Could not write Record bytes to ByteArrayStream", ex);
            }
        }
        return stream.toByteArray();
    }

    @Override
    public void updateEncryptionCipher(RecordCipher encryptionCipher) {
        encryptor.addNewRecordCipher(encryptionCipher);
    }

    @Override
    public void updateDecryptionCipher(RecordCipher decryptionCipher) {
        decryptor.addNewRecordCipher(decryptionCipher);
    }

    @Override
    public AbstractRecord getFreshRecord() {
        return new BlobRecord(context.getChooser().getOutboundMaxRecordDataSize());
    }

    @Override
    public RecordCipher getEncryptorCipher() {
        return encryptor.getRecordMostRecentCipher();
    }

    @Override
    public RecordCipher getDecryptorCipher() {
        return decryptor.getRecordMostRecentCipher();
    }

    @Override
    public void resetEncryptor() {
        encryptor.removeAllCiphers();
    }

    @Override
    public void resetDecryptor() {
        decryptor.removeAllCiphers();
    }

}
