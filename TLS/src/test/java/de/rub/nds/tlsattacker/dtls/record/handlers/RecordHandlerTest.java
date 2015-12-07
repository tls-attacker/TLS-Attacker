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
package de.rub.nds.tlsattacker.dtls.record.handlers;

import de.rub.nds.tlsattacker.dtls.record.messages.Record;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.crypto.TlsRecordBlockCipher;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Florian Pfützenreuter <Florian.Pfuetzenreuter@rub.de>
 */
public class RecordHandlerTest {

    de.rub.nds.tlsattacker.tls.record.handlers.RecordHandler rh;

    TlsContext tlsContext = new TlsContext();

    public RecordHandlerTest() {
	tlsContext.setProtocolVersion(ProtocolVersion.DTLS12);
	tlsContext.setRecordHandler(new RecordHandler(tlsContext));
	rh = tlsContext.getRecordHandler();
    }

    /**
     * Test of wrapData method, of class RecordHandler.
     */
    @Test
    public void testWrapData() {
	LinkedList<de.rub.nds.tlsattacker.tls.record.messages.Record> testRecords = new LinkedList<>();
	byte[] protocolMessageData;
	byte[] expectedResult;
	byte[] result;

	protocolMessageData = ArrayConverter.hexStringToByteArray("6666666666");
	expectedResult = ArrayConverter.hexStringToByteArray("16fefd000000000000000000056666666666");
	testRecords.add(new Record());
	result = rh.wrapData(protocolMessageData, ProtocolMessageType.HANDSHAKE, testRecords);

	assertEquals("Check first result length", expectedResult.length, result.length);
	assertArrayEquals("Check first result content", expectedResult, result);

	protocolMessageData = ArrayConverter.hexStringToByteArray("01");
	expectedResult = ArrayConverter.hexStringToByteArray("14fefd0000000000000001000101");
	testRecords.add(new Record());
	result = rh.wrapData(protocolMessageData, ProtocolMessageType.CHANGE_CIPHER_SPEC, testRecords);

	assertEquals("Check second result length", expectedResult.length, result.length);
	assertArrayEquals("Check second result content", expectedResult, result);

	protocolMessageData = ArrayConverter.hexStringToByteArray("6667778889");
	expectedResult = ArrayConverter.hexStringToByteArray("16fefd000100000000000000056667778889");
	testRecords.add(new Record());
	result = rh.wrapData(protocolMessageData, ProtocolMessageType.HANDSHAKE, testRecords);

	assertEquals("Check third result length", expectedResult.length, result.length);
	assertArrayEquals("Check third result content", expectedResult, result);
    }

    /**
     * Test of parseRecords method, of class RecordHandler.
     */
    @Test
    public void testParseRecords() {
	byte[] testOnWireBytes = ArrayConverter
		.hexStringToByteArray("16fefd00000000000000000005012345678914fefd000000000000000100010116fefd00010000000000"
			+ "0200059876543210");
	List<de.rub.nds.tlsattacker.tls.record.messages.Record> result = rh.parseRecords(testOnWireBytes);

	assertEquals("Check number of records", 3, result.size());
	Record currentRecord = (de.rub.nds.tlsattacker.dtls.record.messages.Record) result.get(0);
	assertEquals("Check first record type", new Byte(ProtocolMessageType.HANDSHAKE.getValue()), currentRecord
		.getContentType().getValue());
	assertArrayEquals("Check first record protocol version", ProtocolVersion.DTLS12.getValue(), currentRecord
		.getProtocolVersion().getValue());
	assertEquals("Check first record epoch", new Integer(0), currentRecord.getEpoch().getValue());
	assertEquals("Check first record sequence number", new BigInteger("0"), currentRecord.getSequenceNumber()
		.getValue());
	assertEquals("Check first record length", new Integer(5), currentRecord.getLength().getValue());
	assertArrayEquals("Check first record protocol message content",
		ArrayConverter.hexStringToByteArray("0123456789"), currentRecord.getProtocolMessageBytes().getValue());

	currentRecord = (de.rub.nds.tlsattacker.dtls.record.messages.Record) result.get(1);
	assertEquals("Check first record type", new Byte(ProtocolMessageType.CHANGE_CIPHER_SPEC.getValue()),
		currentRecord.getContentType().getValue());
	assertArrayEquals("Check first record protocol version", ProtocolVersion.DTLS12.getValue(), currentRecord
		.getProtocolVersion().getValue());
	assertEquals("Check first record epoch", new Integer(0), currentRecord.getEpoch().getValue());
	assertEquals("Check first record sequence number", new BigInteger("1"), currentRecord.getSequenceNumber()
		.getValue());
	assertEquals("Check first record length", new Integer(1), currentRecord.getLength().getValue());
	assertArrayEquals("Check first record protocol message content", ArrayConverter.hexStringToByteArray("01"),
		currentRecord.getProtocolMessageBytes().getValue());

	currentRecord = (de.rub.nds.tlsattacker.dtls.record.messages.Record) result.get(2);
	assertEquals("Check first record type", new Byte(ProtocolMessageType.HANDSHAKE.getValue()), currentRecord
		.getContentType().getValue());
	assertArrayEquals("Check first record protocol version", ProtocolVersion.DTLS12.getValue(), currentRecord
		.getProtocolVersion().getValue());
	assertEquals("Check first record epoch", new Integer(1), currentRecord.getEpoch().getValue());
	assertEquals("Check first record sequence number", new BigInteger("2"), currentRecord.getSequenceNumber()
		.getValue());
	assertEquals("Check first record length", new Integer(5), currentRecord.getLength().getValue());
	assertArrayEquals("Check first record protocol message content",
		ArrayConverter.hexStringToByteArray("9876543210"), currentRecord.getProtocolMessageBytes().getValue());
    }
}
