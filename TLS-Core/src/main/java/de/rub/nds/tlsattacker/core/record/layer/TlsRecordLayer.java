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
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
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

    public TlsRecordLayer(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public List<AbstractRecord> parseRecords(byte[] rawRecordData) {
        List<AbstractRecord> records = new LinkedList<>();
        int dataPointer = 0;
        while (dataPointer != rawRecordData.length) {
            try {
                RecordParser parser =
                    new RecordParser(dataPointer, rawRecordData, getDecryptorCipher().getState().getVersion());
                Record record = parser.parse();
                records.add(record);
                if (dataPointer == parser.getPointer()) {
                    throw new ParserException("Ran into infinite Loop while parsing HttpsHeader");
                }
                dataPointer = parser.getPointer();
            } catch (ParserException e) {
                throw new ParserException("Could not parse provided Data as Record", e);
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
                RecordParser parser =
                    new RecordParser(dataPointer, rawRecordData, getDecryptorCipher().getState().getVersion());
                Record record = parser.parse();
                records.add(record);
                if (dataPointer == parser.getPointer()) {
                    throw new ParserException("Ran into infinite Loop while parsing Records");
                }
                dataPointer = parser.getPointer();
            } catch (ParserException e) {
                LOGGER.debug("Could not parse Record, parsing as Blob");
                LOGGER.trace(e);
                BlobRecordParser blobParser =
                    new BlobRecordParser(dataPointer, rawRecordData, getDecryptorCipher().getState().getVersion());
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
        CleanRecordByteSeperator separator =
            new CleanRecordByteSeperator(records, getTlsContext().getChooser().getOutboundMaxRecordDataSize(), 0, data);
        records = separator.parse();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        boolean useRecordType = false;
        if (contentType == null) {
            useRecordType = true;
        }
        for (AbstractRecord record : records) {
            if (useRecordType) {
                contentType = record.getContentMessageType();
                if (contentType == null) {
                    contentType = ProtocolMessageType.UNKNOWN;
                }
            }
            if (getEncryptorCipher().getState().getVersion().isDTLS() && record instanceof Record) {
                ((Record) record).setEpoch(getWriteEpoch());
            }
            AbstractRecordPreparator preparator =
                record.getRecordPreparator(getTlsContext().getChooser(), getEncryptor(), getCompressor(), contentType);
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
    public byte[] reencrypt(List<AbstractRecord> records) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AbstractRecord record : records) {
            AbstractRecordPreparator preparator = record.getRecordPreparator(getTlsContext().getChooser(),
                getEncryptor(), getCompressor(), record.getContentMessageType());
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
    public void decryptAndDecompressRecord(AbstractRecord record) {
        if (record instanceof Record) {
            if (record.getContentMessageType() == ProtocolMessageType.CHANGE_CIPHER_SPEC
                && getDecryptorCipher().getState().getVersion().isTLS13()) {
                // Do not decrypt the record
                record.prepareComputations();
                byte[] protocolMessageBytes = record.getProtocolMessageBytes().getValue();
                record.setCleanProtocolMessageBytes(protocolMessageBytes);
            } else {
                getDecryptor().decrypt(record);
                getDecompressor().decompress(record);
                ((Record) record).getComputations().setUsedTls13KeySetType(getTlsContext().getActiveKeySetTypeRead());
            }
        } else {
            LOGGER.warn("Decrypting received non Record:" + record.toString());
            getDecryptor().decrypt(record);
            getDecompressor().decompress(record);
        }
    }

    public AbstractRecord getFreshRecord() {
        return new Record(getTlsContext().getChooser().getOutboundMaxRecordDataSize());
    }

}
