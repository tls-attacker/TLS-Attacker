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
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.parser.special.CleanRecordByteSeperator;
import de.rub.nds.tlsattacker.tls.record.AbstractRecord;
import de.rub.nds.tlsattacker.tls.record.BlobRecord;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.tls.record.decryptor.BlobDecryptor;
import de.rub.nds.tlsattacker.tls.record.decryptor.Decryptor;
import de.rub.nds.tlsattacker.tls.record.encryptor.BlobEncryptor;
import de.rub.nds.tlsattacker.tls.record.encryptor.Encryptor;
import de.rub.nds.tlsattacker.tls.record.parser.BlobRecordParser;
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
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BlobRecordLayer extends RecordLayer {

    private final TlsContext context;

    private RecordCipher cipher;
    private final Encryptor encryptor;
    private final Decryptor decryptor;

    public BlobRecordLayer(TlsContext context) {
        this.context = context;
        cipher = new RecordNullCipher();
        encryptor = new BlobEncryptor(cipher);
        decryptor = new BlobDecryptor(cipher);
    }

    @Override
    public List<AbstractRecord> parseRecords(byte[] rawBytes) {
        List<AbstractRecord> list = new LinkedList<>();
        BlobRecordParser parser = new BlobRecordParser(0, rawBytes, context.getSelectedProtocolVersion());
        list.add(parser.parse());
        return list;
    }

    @Override
    public void decryptRecord(AbstractRecord record) {
        byte[] data = record.getProtocolMessageBytes().getValue();
        data = cipher.decrypt(data);
        record.setCleanProtocolMessageBytes(data);
    }

    @Override
    public byte[] prepareRecords(byte[] data, ProtocolMessageType contentType, List<AbstractRecord> records) {
        CleanRecordByteSeperator seperator = new CleanRecordByteSeperator(records, context.getConfig()
                .getDefaultMaxRecordData(), 0, data);
        records = seperator.parse();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AbstractRecord record : records) {
            AbstractRecordPreparator preparator = record.getRecordPreparator(context, encryptor, contentType);
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
    public AbstractRecord getFreshRecord() {
        return new BlobRecord();
    }

}
