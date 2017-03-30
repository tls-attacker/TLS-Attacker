/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.dtls.record;

import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Florian Pfützenreuter <Florian.Pfuetzenreuter@rub.de>
 */
public class DtlsRecordHandler extends RecordHandler {

    private static final Logger LOGGER = LogManager
            .getLogger(de.rub.nds.tlsattacker.dtls.record.DtlsRecordHandler.class);

    private long sequenceCounter, lastEpochSequenceCounter;

    private int epochCounter;

    public DtlsRecordHandler(TlsContext tlsContext) {
        super(tlsContext);
        if (tlsContext.getSelectedProtocolVersion() != ProtocolVersion.DTLS12) {
            if (tlsContext.getSelectedProtocolVersion() == ProtocolVersion.DTLS10) {
                throw new UnsupportedOperationException("DTLSv1.0 is not supported.");
            }
            throw new ConfigurationException("The workflow was configured with an unsuitable protocol.");
        }
        sequenceCounter = 0;
    }

    @Override
    public byte[] wrapData(byte[] data, ProtocolMessageType contentType, List<Record> records) {

        // if there are no records defined, we throw an exception
        if (records == null || records.isEmpty()) {
            throw new WorkflowExecutionException("No records to be written in");
        }

        int dataPointer = 0;
        int currentRecord = 0;
        while (dataPointer != data.length) {
            // we check if there are enough records to be written in
            if (records.size() == currentRecord) {
                // TODO The RecordHandler should not add records without beeing
                // asked to
                records.add(new Record());
            }
            Record record = records.get(currentRecord);
            // fill record with data
            dataPointer = fillRecord( record, contentType, data,
                    dataPointer);
            if (contentType == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                advanceEpoch();
            }
            currentRecord++;
        }

        // remove records that we did not need
        while (currentRecord != records.size()) {
            records.remove(currentRecord);
        }

        // create resulting byte array
        byte[] result = new byte[0];
        for (Record record : records) {
            byte[] ctArray = { record.getContentType().getValue() };
            byte[] pv = record.getProtocolVersion().getValue();
            byte[] en = ArrayConverter.intToBytes(record.getEpoch().getValue(), RecordByteLength.EPOCH);
            byte[] sn = ArrayConverter.bigIntegerToNullPaddedByteArray(record.getSequenceNumber().getValue(),
                    RecordByteLength.SEQUENCE_NUMBER);
            byte[] rl = ArrayConverter.intToBytes(record.getLength().getValue(), RecordByteLength.RECORD_LENGTH);
            if (!encryptSending || contentType == ProtocolMessageType.CHANGE_CIPHER_SPEC || epochCounter < 1) {
                byte[] pm = record.getProtocolMessageBytes().getValue();
                result = ArrayConverter.concatenate(result, ctArray, pv, en, sn, rl, pm);
            } else {
                byte[] epm = record.getEncryptedProtocolMessageBytes().getValue();
                result = ArrayConverter.concatenate(result, ctArray, pv, en, sn, rl, epm);
            }
        }
        LOGGER.debug("The protocol message(s) was split into {} record(s).", records.size());

        return result;
    }

    /**
     * Takes the data going to be sent and wraps it inside of the record. It
     * returns the size of the data, which were currently wrapped in the records
     * (it is namely possible to divide Protocol message data into several
     * records).
     * 
     * @param record
     *            record going to be filled in
     * @param contentType
     *            content type
     * @param data
     *            data array
     * @param dataPointer
     *            current position in the read data
     * @return new position of the data going to be sent in the records
     */
    private int fillRecord(Record record, ProtocolMessageType contentType,
            byte[] data, int dataPointer) {
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

        record.setSequenceNumber(BigInteger.valueOf(sequenceCounter));
        record.setEpoch(epochCounter);
        record.setLength(pmData.length);
        record.setProtocolMessageBytes(pmData);

        if (recordCipher != null && contentType != ProtocolMessageType.CHANGE_CIPHER_SPEC && epochCounter > 0) {
            byte[] mac = recordCipher.calculateDtlsMac(tlsContext.getSelectedProtocolVersion(), contentType, record
                    .getProtocolMessageBytes().getValue(), record.getSequenceNumber().getValue().longValue(), record
                    .getEpoch().getValue());
            record.setMac(mac);
            byte[] macedData = ArrayConverter.concatenate(record.getProtocolMessageBytes().getValue(), record.getMac()
                    .getValue());
            int paddingLength = recordCipher.calculatePaddingLength(macedData.length);
            record.setPaddingLength(paddingLength);
            byte[] padding = recordCipher.calculatePadding(record.getPaddingLength().getValue());
            record.setPadding(padding);
            byte[] paddedMacedData = ArrayConverter.concatenate(macedData, record.getPadding().getValue());
            record.setPlainRecordBytes(paddedMacedData);
            LOGGER.debug("Padded data before encryption:  {}",
                    ArrayConverter.bytesToHexString(record.getPlainRecordBytes().getValue()));
            byte[] encData = recordCipher.encrypt(record.getPlainRecordBytes().getValue());
            record.setEncryptedProtocolMessageBytes(encData);
            record.setLength(encData.length);
            LOGGER.debug("Padded data after encryption:  {}", ArrayConverter.bytesToHexString(encData));
        }

        sequenceCounter++;

        return returnPointer;
    }

    @Override
    public List<Record> parseRecords(byte[] rawRecordData) {

        List<Record> records = new LinkedList<>();
        int dataPointer = 0;
        while (dataPointer < rawRecordData.length) {
            ProtocolMessageType contentType = ProtocolMessageType.getContentType(rawRecordData[dataPointer]);
            if (contentType == null) {
                throw new WorkflowExecutionException("Could not identify valid protocol message type for the current "
                        + "record. The value in the record was: " + rawRecordData[dataPointer]);
            }
            Record record = new Record();
            record.setContentType(contentType.getValue());

            byte[] protocolVersion = { rawRecordData[dataPointer + 1], rawRecordData[dataPointer + 2] };
            record.setProtocolVersion(protocolVersion);

            byte[] byteEpoch = { rawRecordData[dataPointer + 3], rawRecordData[dataPointer + 4] };
            int epoch = ArrayConverter.bytesToInt(byteEpoch);
            record.setEpoch(epoch);

            byte[] byteSequenceNumber = { rawRecordData[dataPointer + 5], rawRecordData[dataPointer + 6],
                    rawRecordData[dataPointer + 7], rawRecordData[dataPointer + 8], rawRecordData[dataPointer + 9],
                    rawRecordData[dataPointer + 10] };
            BigInteger sequenceNumber = new BigInteger(1, byteSequenceNumber);
            record.setSequenceNumber(sequenceNumber);

            byte[] byteLength = { rawRecordData[dataPointer + 11], rawRecordData[dataPointer + 12] };
            int length = ArrayConverter.bytesToInt(byteLength);
            record.setLength(length);

            int lastByte = dataPointer + 13 + length;
            byte[] rawBytesFromCurrentRecord = Arrays.copyOfRange(rawRecordData, dataPointer + 13, lastByte);
            LOGGER.debug("Raw protocol bytes from the current parsed record:  {}",
                    ArrayConverter.bytesToHexString(rawBytesFromCurrentRecord));

            if (decryptReceiving && (contentType != ProtocolMessageType.CHANGE_CIPHER_SPEC)
                    && (recordCipher != null && recordCipher.getMinimalEncryptedRecordLength() <= length)) {
                record.setEncryptedProtocolMessageBytes(rawBytesFromCurrentRecord);
                byte[] paddedData = recordCipher.decrypt(rawBytesFromCurrentRecord);
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

            if (contentType == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                decryptReceiving = true;
            }
        }
        LOGGER.debug("The protocol message(s) were collected from {} record(s). ", records.size());

        return records;
    }

    private void advanceEpoch() {
        epochCounter++;
        lastEpochSequenceCounter = sequenceCounter;
        sequenceCounter = 0;
    }

    public void revertEpoch() {
        if (epochCounter > 0) {
            epochCounter--;
            sequenceCounter = lastEpochSequenceCounter;
        }
    }

    public int getEpoch() {
        return epochCounter;
    }
}
