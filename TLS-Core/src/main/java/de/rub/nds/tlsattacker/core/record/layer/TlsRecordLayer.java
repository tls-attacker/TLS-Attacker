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
import de.rub.nds.tlsattacker.core.protocol.parser.special.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
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

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TlsRecordLayer extends RecordLayer {

    protected final TlsContext tlsContext;

    private final Decryptor decryptor;
    private final Encryptor encryptor;

    private RecordCipher cipher;

    public TlsRecordLayer(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
        cipher = new RecordNullCipher();
        encryptor = new RecordEncryptor(cipher, tlsContext);
        decryptor = new RecordDecryptor(cipher, tlsContext);
    }

    /**
     *
     * @param rawRecordData
     * @return list of parsed records or null, if there was not enough data
     */
    @Override
    public List<AbstractRecord> parseRecords(byte[] rawRecordData) {

        List<AbstractRecord> records = new LinkedList<>();
        int dataPointer = 0;
        while (dataPointer != rawRecordData.length) {
            try {
                RecordParser parser = new RecordParser(dataPointer, rawRecordData,
                        tlsContext.getSelectedProtocolVersion());
                Record record = parser.parse();
                records.add(record);
                dataPointer = parser.getPointer();
            } catch (ParserException E) {
                // TODO Could not parse as record try parsing Blob
                BlobRecordParser blobParser = new BlobRecordParser(dataPointer, rawRecordData,
                        tlsContext.getSelectedProtocolVersion());
                AbstractRecord record = blobParser.parse();
                records.add(record);
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
        for (AbstractRecord record : records) {
            AbstractRecordPreparator preparator = record.getRecordPreparator(tlsContext.getChooser(), encryptor,
                    contentType);
            preparator.prepare();
            AbstractRecordSerializer serializer = record.getRecordSerializer();
            try {
                stream.write(serializer.serialize());
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
    public void decryptRecord(AbstractRecord record) {
        if (record instanceof Record) {
            try {
                decryptor.decrypt(record);
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

}
