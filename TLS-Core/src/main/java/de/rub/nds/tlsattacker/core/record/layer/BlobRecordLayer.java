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
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
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

    public BlobRecordLayer(TlsContext context) {
        super(context);
    }

    @Override
    public List<AbstractRecord> parseRecords(byte[] rawBytes) {
        List<AbstractRecord> list = new LinkedList<>();
        BlobRecordParser parser =
            new BlobRecordParser(0, rawBytes, getTlsContext().getChooser().getSelectedProtocolVersion());
        list.add(parser.parse());
        return list;
    }

    @Override
    public List<AbstractRecord> parseRecordsSoftly(byte[] rawBytes) {
        return parseRecords(rawBytes);
    }

    @Override
    public void decryptAndDecompressRecord(AbstractRecord record) {
        getDecryptor().decrypt(record);
        getDecompressor().decompress(record);
    }

    @Override
    public byte[] prepareRecords(byte[] data, ProtocolMessageType contentType, List<AbstractRecord> records) {
        CleanRecordByteSeperator separator =
            new CleanRecordByteSeperator(records, getTlsContext().getChooser().getOutboundMaxRecordDataSize(), 0, data);
        records = separator.parse();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AbstractRecord record : records) {
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
    public AbstractRecord getFreshRecord() {
        return new BlobRecord(getTlsContext().getChooser().getOutboundMaxRecordDataSize());
    }

}
