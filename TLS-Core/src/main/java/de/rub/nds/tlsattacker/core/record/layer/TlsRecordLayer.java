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
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.compressor.RecordDecompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Decryptor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordEncryptor;
import de.rub.nds.tlsattacker.core.record.parser.BlobRecordParser;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.AbstractRecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.AbstractRecordSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsRecordLayer extends RecordLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final TlsContext tlsContext;

    private final Decryptor decryptor;
    private final Encryptor encryptor;

    private RecordCompressor compressor;
    private RecordDecompressor decompressor;

    private RecordCipher cipher;

    public TlsRecordLayer(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
        cipher = new RecordNullCipher(tlsContext);
        encryptor = new RecordEncryptor(cipher, tlsContext);
        decryptor = new RecordDecryptor(cipher, tlsContext);
        compressor = new RecordCompressor(tlsContext);
        decompressor = new RecordDecompressor(tlsContext);
    }

    /**
     * @param rawRecordData
     *            The RawRecordData that should be parsed
     * @return list of parsed records or null, if there was not enough data
     */

    @Override
    public void updateCompressor() {
        compressor.setMethod(tlsContext.getChooser().getSelectedCompressionMethod());
    }

    @Override
    public void updateDecompressor() {
        decompressor.setMethod(tlsContext.getChooser().getSelectedCompressionMethod());
    }

    @Override
    public List<AbstractRecord> parseRecords(byte[] rawRecordData) {
        List<AbstractRecord> records = new LinkedList<>();
        int dataPointer = 0;
        while (dataPointer != rawRecordData.length) {
            try {
                RecordParser parser = new RecordParser(dataPointer, rawRecordData, tlsContext.getChooser()
                        .getSelectedProtocolVersion());
                Record record = parser.parse();
                records.add(record);
                if (dataPointer == parser.getPointer()) {
                    throw new ParserException("Ran into infinite Loop while parsing HttpsHeader");
                }
                dataPointer = parser.getPointer();
            } catch (ParserException E) {
                throw new ParserException("Could not parse provided Data as Record", E);
            }
        }
        LOGGER.debug("The protocol message(s) were collected from {} record(s). ", records.size());
        return records;
    }

    @Override
    public List<AbstractRecord> parseRecordsSoftly(byte[] rawRecordData) {
        List<AbstractRecord> records = new LinkedList<>();
        int dataPointer = 0;
        while (dataPointer != rawRecordData.length) {
            try {
                RecordParser parser = new RecordParser(dataPointer, rawRecordData, tlsContext.getChooser()
                        .getSelectedProtocolVersion());
                Record record = parser.parse();
                records.add(record);
                if (dataPointer == parser.getPointer()) {
                    throw new ParserException("Ran into infinite Loop while parsing Records");
                }
                dataPointer = parser.getPointer();
            } catch (ParserException E) {
                LOGGER.debug("Could not parse Record, parsing as Blob");
                LOGGER.trace(E);
                BlobRecordParser blobParser = new BlobRecordParser(dataPointer, rawRecordData, tlsContext.getChooser()
                        .getSelectedProtocolVersion());
                AbstractRecord record = blobParser.parse();
                records.add(record);
                if (dataPointer == blobParser.getPointer()) {
                    throw new ParserException("Ran into infinite Loop while parsing BlobRecords");
                }
                dataPointer = blobParser.getPointer();
            }
        }
        LOGGER.debug("The protocol message(s) were collected from {} record(s). ", records.size());
        return records;
    }

    @Override
    public byte[] prepareRecords(byte[] data, ProtocolMessageType contentType, List<AbstractRecord> records) {
        CleanRecordByteSeperator seperator = new CleanRecordByteSeperator(records, tlsContext.getConfig()
                .getDefaultMaxRecordData(), 0, data);
        records = seperator.parse();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        boolean useRecordType = false;
        if (contentType == null) {
            useRecordType = true;
        }
        for (AbstractRecord record : records) {
            if (useRecordType) {
                contentType = record.getContentMessageType();
            }

            AbstractRecordPreparator preparator = record.getRecordPreparator(tlsContext.getChooser(), encryptor,
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

    public RecordCipher getRecordCipher() {
        return cipher;
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
    // TODO for DTLS we should memorize the cipher (states) for every epoch
    // which would allow us to select the cipher depending on the cipher in the
    // epoch
    public void decryptRecord(AbstractRecord record) {
        if (record instanceof Record) {
            try {
                if (tlsContext.isTls13SoftDecryption()
                        && tlsContext.getTalkingConnectionEndType() != tlsContext.getConnection()
                                .getLocalConnectionEndType()) {
                    if (null == ((Record) record).getContentMessageType()) {
                        LOGGER.debug("Deactivating soft decryption since we received a non alert record");
                        tlsContext.setTls13SoftDecryption(false);
                    } else {
                        switch (((Record) record).getContentMessageType()) {
                            case ALERT:
                                LOGGER.warn("Received Alert record while soft Decryption is active. Setting RecordCipher back to null");
                                setRecordCipher(new RecordNullCipher(tlsContext));
                                updateDecryptionCipher();
                                break;
                            case CHANGE_CIPHER_SPEC:
                                LOGGER.debug("Received CCS in TLS 1.3 compatibility mode");
                                record.setCleanProtocolMessageBytes(record.getProtocolMessageBytes().getValue());
                                return;
                            default:
                                LOGGER.debug("Deactivating soft decryption since we received a non alert record");
                                tlsContext.setTls13SoftDecryption(false);
                                break;
                        }
                    }
                }
                decryptor.decrypt(record);
                decompressor.decompress(record);
            } catch (CryptoException E) {
                record.setCleanProtocolMessageBytes(record.getProtocolMessageBytes().getValue());
                LOGGER.warn("Could not decrypt Record, parsing as unencrypted");
                LOGGER.debug(E);
            }
        } else {
            LOGGER.warn("Not decrypting received non Record:" + record.toString());
            record.setCleanProtocolMessageBytes(record.getProtocolMessageBytes());
        }
    }

    @Override
    public AbstractRecord getFreshRecord() {
        return new Record(tlsContext.getConfig());
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
