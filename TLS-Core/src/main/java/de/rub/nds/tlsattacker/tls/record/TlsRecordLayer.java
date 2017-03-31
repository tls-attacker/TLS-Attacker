/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record;

import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordBlockCipher;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.tls.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.tls.record.decryptor.RecordDecryptor;
import de.rub.nds.tlsattacker.tls.record.encryptor.RecordEncryptor;
import de.rub.nds.tlsattacker.tls.record.parser.RecordParser;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
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

    private RecordDecryptor decryptor;
    private RecordEncryptor encryptor;

    public TlsRecordLayer(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
        RecordCipher cipher = new RecordNullCipher();
        encryptor = new RecordEncryptor(cipher);
        decryptor = new RecordDecryptor(cipher);
    }

    /**
     * Takes the data going to be sent and wraps it inside of the record. It
     * returns the size of the data, which were currently wrapped in the records
     * (it is namely possible to divide Protocol message data into several
     * records).
     *
     * @param record record going to be filled in
     * @param contentType content type
     * @param data data array
     * @param dataPointer current position in the read data
     * @return new position of the data going to be sent in the records
     */
    private int fillRecord(Record record, ProtocolMessageType contentType, byte[] data, int dataPointer) {
        record.setContentType(contentType.getValue());
        record.setProtocolVersion(tlsContext.getSelectedProtocolVersion().getValue());
        byte[] pmData;
        int returnPointer = data.length;
        pmData = Arrays.copyOfRange(data, dataPointer, data.length);
        if (record.getMaxRecordLengthConfig() != null) {
            int missingLength = data.length - dataPointer;
            if (record.getMaxRecordLengthConfig() < missingLength) {
                pmData = Arrays.copyOfRange(data, dataPointer, (dataPointer + record.getMaxRecordLengthConfig()));
                returnPointer = (dataPointer + record.getMaxRecordLengthConfig());
            }
        }
        record.setCleanProtocolMessageBytes(pmData);
        encryptor.encrypt(record);
        record.setLength(record.getProtocolMessageBytes().getValue().length);
        return returnPointer;
    }

    /**
     *
     * @param rawRecordData
     * @return list of parsed records or null, if there was not enough data
     */
    public List<Record> parseRecords(byte[] rawRecordData) {

        List<Record> records = new LinkedList<>();
        int dataPointer = 0;
        while (dataPointer != rawRecordData.length) {
            RecordParser parser = new RecordParser(dataPointer, rawRecordData, tlsContext.getSelectedProtocolVersion());
            Record record = parser.parse();
            decryptor.decrypt(record);
            dataPointer = parser.getPointer();
            // store Finished raw bytes to set TLS Record Cipher before parsing
            // them into a record
            if (record.getContentType().getValue() == ProtocolMessageType.CHANGE_CIPHER_SPEC.getValue()) {
                decryptor.setRecordCipher(RecordCipherFactory.getRecordCipher(tlsContext));
            }
            if (decryptReceiving && (contentType != ProtocolMessageType.CHANGE_CIPHER_SPEC)
                    && (recordCipher.getMinimalEncryptedRecordLength() <= length)) {
                record.setEncryptedProtocolMessageBytes(rawBytesFromCurrentRecord);
                byte[] paddedData = recordCipher.decrypt(rawBytesFromCurrentRecord);
                record.setPlainRecordBytes(paddedData);
                LOGGER.debug("Padded data after decryption:  {}", ArrayConverter.bytesToHexString(paddedData));
                int paddingLength = paddedData[paddedData.length - 1];
                record.setPaddingLength(paddingLength);
                int paddingStart = paddedData.length - paddingLength - 1;
                byte[] unpaddedData = Arrays.copyOf(paddedData, paddingStart);
                record.setPadding(Arrays.copyOfRange(paddedData, paddingStart, paddedData.length));
                LOGGER.debug("Unpadded data:  {}", ArrayConverter.bytesToHexString(unpaddedData));
                byte[] mac = Arrays.copyOfRange(unpaddedData, (unpaddedData.length - recordCipher.getMacLength()),
                        unpaddedData.length);
                record.setMac(mac);
                rawBytesFromCurrentRecord = Arrays.copyOf(unpaddedData,
                        (unpaddedData.length - recordCipher.getMacLength()));
            }
            record.setProtocolMessageBytes(rawBytesFromCurrentRecord);
            records.add(record);
            dataPointer = lastByte;

        }
        LOGGER.debug("The protocol message(s) were collected from {} record(s). ", records.size());

        return records;
    }

    public RecordBlockCipher getRecordCipher() {
        return recordCipher;
    }

    public void setRecordCipher(RecordBlockCipher recordCipher) {
        this.recordCipher = recordCipher;
    }

    /**
     * Parses stored finish bytes into records and sets the stored finished
     * bytes to null. Returns null if no records were parsed
     *
     * @return List of parsed Records
     */
    public List<Record> parseFinishedBytes() {
        if (finishedBytes == null) {
            return null;
        } else {
            List<Record> records = parseRecords(finishedBytes);
            finishedBytes = null;
            return records;
        }
    }

    @Override
    public byte[] prepareRecords(byte[] data, ProtocolMessageType contentType, List<Record> records) {

        // if there are no records defined, we throw an exception
        if (records == null || records.isEmpty()) {
            throw new WorkflowExecutionException("No records to be written in");
        }

        int dataPointer = 0;
        int currentRecord = 0;
        while (dataPointer != data.length) {
            // we check if there are enough records to be written in
            if (records.size() == currentRecord) {
                records.add(new Record());// TODO i dont think we want to
                // manipulate the handshake here
            }
            Record record = records.get(currentRecord);
            // fill record with data
            dataPointer = fillRecord(record, contentType, data, dataPointer);
            currentRecord++;
        }

        // remove records that we did not need
        while (currentRecord != records.size()) {
            records.remove(currentRecord);// TODO i dont think we want to
            // manipulate the handshake here
        }

        // create resulting byte array
        byte[] result = new byte[0];
        for (Record record : records) {
            byte[] ctArray = {record.getContentType().getValue()};
            byte[] pv = record.getProtocolVersion().getValue();
            byte[] rl = ArrayConverter.intToBytes(record.getLength().getValue(), RecordByteLength.RECORD_LENGTH);
            if (contentType == ProtocolMessageType.CHANGE_CIPHER_SPEC || !encryptSending) {
                byte[] pm = record.getProtocolMessageBytes().getValue();
                result = ArrayConverter.concatenate(result, ctArray, pv, rl, pm);
            } else {
                byte[] epm = record.getEncryptedProtocolMessageBytes().getValue();
                result = ArrayConverter.concatenate(result, ctArray, pv, rl, epm);
            }
        }
        // LOGGER.debug("The protocol message(s) was split into {} record(s). The result is: {}",
        // records.size(),
        // ArrayConverter.bytesToHexString(result));
        LOGGER.debug("The protocol message(s) was split into {} record(s).", records.size());

        return result;
    }
}
