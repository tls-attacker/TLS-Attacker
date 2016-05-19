/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.dtls.record;

import de.rub.nds.tlsattacker.dtls.record.DtlsRecordHandler;
import de.rub.nds.tlsattacker.dtls.record.DtlsRecord;
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

    de.rub.nds.tlsattacker.tls.record.RecordHandler rh;

    TlsContext tlsContext = new TlsContext();

    public RecordHandlerTest() {
	tlsContext.setProtocolVersion(ProtocolVersion.DTLS12);
	tlsContext.setRecordHandler(new DtlsRecordHandler(tlsContext));
	rh = tlsContext.getRecordHandler();
    }

    /**
     * Test of wrapData method, of class DtlsRecordHandler.
     */
    @Test
    public void testWrapData() {
	LinkedList<de.rub.nds.tlsattacker.tls.record.Record> testRecords = new LinkedList<>();
	byte[] protocolMessageData;
	byte[] expectedResult;
	byte[] result;

	protocolMessageData = ArrayConverter.hexStringToByteArray("6666666666");
	expectedResult = ArrayConverter.hexStringToByteArray("16fefd000000000000000000056666666666");
	testRecords.add(new DtlsRecord());
	result = rh.wrapData(protocolMessageData, ProtocolMessageType.HANDSHAKE, testRecords);

	assertEquals("Check first result length", expectedResult.length, result.length);
	assertArrayEquals("Check first result content", expectedResult, result);

	protocolMessageData = ArrayConverter.hexStringToByteArray("01");
	expectedResult = ArrayConverter.hexStringToByteArray("14fefd0000000000000001000101");
	testRecords.add(new DtlsRecord());
	result = rh.wrapData(protocolMessageData, ProtocolMessageType.CHANGE_CIPHER_SPEC, testRecords);

	assertEquals("Check second result length", expectedResult.length, result.length);
	assertArrayEquals("Check second result content", expectedResult, result);

	protocolMessageData = ArrayConverter.hexStringToByteArray("6667778889");
	expectedResult = ArrayConverter.hexStringToByteArray("16fefd000100000000000000056667778889");
	testRecords.add(new DtlsRecord());
	result = rh.wrapData(protocolMessageData, ProtocolMessageType.HANDSHAKE, testRecords);

	assertEquals("Check third result length", expectedResult.length, result.length);
	assertArrayEquals("Check third result content", expectedResult, result);
    }

    /**
     * Test of parseRecords method, of class DtlsRecordHandler.
     */
    @Test
    public void testParseRecords() {
	byte[] testOnWireBytes = ArrayConverter
		.hexStringToByteArray("16fefd00000000000000000005012345678914fefd000000000000000100010116fefd00010000000000"
			+ "0200059876543210");
	List<de.rub.nds.tlsattacker.tls.record.Record> result = rh.parseRecords(testOnWireBytes);

	assertEquals("Check number of records", 3, result.size());
	DtlsRecord currentRecord = (de.rub.nds.tlsattacker.dtls.record.DtlsRecord) result.get(0);
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

	currentRecord = (de.rub.nds.tlsattacker.dtls.record.DtlsRecord) result.get(1);
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

	currentRecord = (de.rub.nds.tlsattacker.dtls.record.DtlsRecord) result.get(2);
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
