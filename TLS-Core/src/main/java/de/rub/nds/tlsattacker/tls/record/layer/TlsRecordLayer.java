/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.layer;

import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.ParserException;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.tls.protocol.parser.special.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.tls.record.AbstractRecord;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.tls.record.decryptor.Decryptor;
import de.rub.nds.tlsattacker.tls.record.decryptor.RecordDecryptor;
import de.rub.nds.tlsattacker.tls.record.encryptor.Encryptor;
import de.rub.nds.tlsattacker.tls.record.encryptor.RecordEncryptor;
import de.rub.nds.tlsattacker.tls.record.parser.RecordParser;
import de.rub.nds.tlsattacker.tls.record.preparator.AbstractRecordPreparator;
import de.rub.nds.tlsattacker.tls.record.serializer.AbstractRecordSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TlsRecordLayer extends RecordLayer {

    private static final Logger LOGGER = LogManager.getLogger(TlsRecordLayer.class);

    protected final TlsContext tlsContext;

    private final Decryptor decryptor;
    private final Encryptor encryptor;

    private RecordCipher cipher;

    public TlsRecordLayer(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
        cipher = new RecordNullCipher();
        encryptor = new RecordEncryptor(cipher);
        decryptor = new RecordDecryptor(cipher);
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
            AbstractRecordPreparator preparator = record.getRecordPreparator(tlsContext, encryptor, contentType);
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
        decryptor.decrypt(record);
    }

}
