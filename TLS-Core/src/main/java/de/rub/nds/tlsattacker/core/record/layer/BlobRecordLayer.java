/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.layer;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
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

public class BlobRecordLayer extends RecordLayer {

    private final TlsContext context;

    private RecordCipher cipher;
    private final Encryptor encryptor;
    private final Decryptor decryptor;
    private RecordCompressor compressor;
    private RecordDecompressor decompressor;

    public BlobRecordLayer(TlsContext context) {
        this.context = context;
        cipher = new RecordNullCipher(context);
        encryptor = new RecordEncryptor(cipher, context);
        decryptor = new RecordDecryptor(cipher, context);
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
    public void decryptRecord(AbstractRecord record) {
        byte[] data = record.getProtocolMessageBytes().getValue();
        data = cipher.decrypt(new DecryptionRequest(null, data)).getDecryptedCipherText();
        record.setCleanProtocolMessageBytes(data);
        decompressor.decompress(record);
    }

    @Override
    public byte[] prepareRecords(byte[] data, ProtocolMessageType contentType, List<AbstractRecord> records) {
        CleanRecordByteSeperator seperator = new CleanRecordByteSeperator(records, context.getConfig()
                .getDefaultMaxRecordData(), 0, data);
        records = seperator.parse();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AbstractRecord record : records) {
            AbstractRecordPreparator preparator = record.getRecordPreparator(context.getChooser(), encryptor,
                    compressor, contentType);
            preparator.prepare();
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
    public void setRecordCipher(RecordCipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public void updateEncryptionCipher() {
        encryptor.setRecordCipher(cipher);
    }

    @Override
    public void updateDecryptionCipher() {
        decryptor.setRecordCipher(cipher);
    }

    @Override
    public AbstractRecord getFreshRecord() {
        return new BlobRecord(context.getConfig());
    }

    @Override
    public RecordCipher getEncryptor() {
        return encryptor.getRecordCipher();
    }

    @Override
    public RecordCipher getDecryptor() {
        return decryptor.getRecordCipher();
    }

}
