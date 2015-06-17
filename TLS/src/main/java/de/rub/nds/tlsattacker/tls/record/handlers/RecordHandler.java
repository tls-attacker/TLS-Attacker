/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.record.handlers;

import de.rub.nds.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.record.constants.ByteLength;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.record.messages.Record;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class RecordHandler {

    private static final Logger LOGGER = LogManager.getLogger(RecordHandler.class);

    private final TlsContext tlsContext;

    private TlsRecordBlockCipher recordCipher;

    private static RecordHandler instance;

    private RecordHandler(TlsContext tlsContext) {
	this.tlsContext = tlsContext;
	recordCipher = null;
	if (tlsContext == null) {
	    throw new ConfigurationException("The workflow was not configured properly, "
		    + "it is not included in the ProtocolController");
	}
    }

    public static RecordHandler getInstance() {
	return instance;
    }

    // todo this is bad for future multi threading processing
    public static RecordHandler createInstance(TlsContext tlsContext) {
	instance = new RecordHandler(tlsContext);
	return instance;
    }

    public byte[] wrapData(byte[] data, ProtocolMessageType contentType, List<Record> records) {

	// if there are no records defined, we throw an exception
	if (records == null || records.isEmpty()) {
	    throw new WorkflowExecutionException("No records to be write in");
	}

	int dataPointer = 0;
	int currentRecord = 0;
	while (dataPointer != data.length) {
	    // we check if there are enough records to be written in
	    if (records.size() == currentRecord) {
		records.add(new Record());
	    }
	    Record record = records.get(currentRecord);
	    // fill record with data
	    dataPointer = fillRecord(record, contentType, data, dataPointer);
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
	    byte[] rl = ArrayConverter.intToBytes(record.getLength().getValue(), ByteLength.RECORD_LENGTH);
	    if (recordCipher == null || contentType == ProtocolMessageType.CHANGE_CIPHER_SPEC) {
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
    private int fillRecord(Record record, ProtocolMessageType contentType, byte[] data, int dataPointer) {
	record.setContentType(contentType.getValue());
	record.setProtocolVersion(tlsContext.getProtocolVersion().getValue());
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
	record.setLength(pmData.length);
	record.setProtocolMessageBytes(pmData);

	if (recordCipher != null && contentType != ProtocolMessageType.CHANGE_CIPHER_SPEC) {
	    byte[] mac = recordCipher.calculateMac(tlsContext.getProtocolVersion(), contentType, record
		    .getProtocolMessageBytes().getValue());
	    record.setMac(mac);
	    byte[] macedData = ArrayConverter.concatenate(record.getProtocolMessageBytes().getValue(), record.getMac()
		    .getValue());
	    int paddingLength = recordCipher.calculatePaddingLength(macedData.length);
	    record.setPaddingLength(paddingLength);
	    byte[] padding = recordCipher.calculatePadding(record.getPaddingLength().getValue());
	    record.setPadding(padding);
	    byte[] paddedData = ArrayConverter.concatenate(macedData, record.getPadding().getValue());
	    LOGGER.debug("Padded data before encryption:  {}", ArrayConverter.bytesToHexString(paddedData));
	    byte[] encData = recordCipher.encrypt(paddedData);
	    record.setEncryptedProtocolMessageBytes(encData);
	    record.setLength(encData.length);
	    LOGGER.debug("Padded data after encryption:  {}", ArrayConverter.bytesToHexString(encData));
	}

	return returnPointer;
    }

    public List<Record> parseRecords(byte[] rawRecordData) {

	List<Record> records = new LinkedList<>();
	int dataPointer = 0;
	while (dataPointer != rawRecordData.length) {
	    ProtocolMessageType contentType = ProtocolMessageType.getContentType(rawRecordData[dataPointer]);
	    if (contentType == null) {
		throw new WorkflowExecutionException("Could not identify valid protocol message type for the current "
			+ "record. The value in the record was: " + rawRecordData[dataPointer]);
	    }
	    Record record = new Record();
	    record.setContentType(contentType.getValue());
	    byte[] protocolVersion = { rawRecordData[dataPointer + 1], rawRecordData[dataPointer + 2] };
	    record.setProtocolVersion(protocolVersion);
	    byte[] byteLength = { rawRecordData[dataPointer + 3], rawRecordData[dataPointer + 4] };
	    int length = ArrayConverter.bytesToInt(byteLength);
	    record.setLength(length);
	    int lastByte = dataPointer + 5 + length;
	    byte[] rawBytesFromCurrentRecord = Arrays.copyOfRange(rawRecordData, dataPointer + 5, lastByte);
	    LOGGER.debug("Raw protocol bytes from the current record:  {}",
		    ArrayConverter.bytesToHexString(rawBytesFromCurrentRecord));

	    if ((recordCipher != null) && (contentType != ProtocolMessageType.CHANGE_CIPHER_SPEC)
		    && (recordCipher.getMinimalEncryptedRecordLength() <= length)) {
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

	    // if (contentType == ProtocolMessageType.HANDSHAKE) {
	    // // update digest over hansdhake data
	    // digest.update(plainMessageBytes);
	    // }
	}
	LOGGER.debug("The protocol message(s) were collected from {} record(s). ", records.size());

	return records;
    }

    public TlsRecordBlockCipher getRecordCipher() {
	return recordCipher;
    }

    public void setRecordCipher(TlsRecordBlockCipher recordCipher) {
	this.recordCipher = recordCipher;
    }
}
