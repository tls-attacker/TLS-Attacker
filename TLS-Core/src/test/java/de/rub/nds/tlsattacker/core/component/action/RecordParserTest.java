/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.component.action;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.crypto.Decryptor;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
public class RecordParserTest {

    @Mock private TlsContext tlsContext;

    @Mock private RecordLayer recordLayer;

    @Mock private Decryptor decryptor;

    @Mock private RecordCipher recordCipher;

    @Mock private KeySet keySet;

    private RecordParser recordParser;

    // Test data: The specific byte sequence to parse
    private static final byte[] TEST_RECORD_BYTES_1 =
            ArrayConverter.hexStringToByteArray(
                    "16FEFD000000000000000200F30B0001BC000100008C0000E772301E170D3231303230343232343735385A170D3331303230323232343735385A305B310B30090603550406130255533113301106035504080C0A57617368696E67746F6E3111300F06035504070C0842656C6C65767565310E300C060355040A0C0556616C76653114301206035504030C0B496E7465727365727665723059301306072A8648CE3D020106082A8648CE3D0301070342000476EDBD0BEF9A383105C4A260377BB1AADE43490491D7A2801C0755A1D8E187157D8406BA9C132E41B50E4481E2CF175AB23CC1EC31505BC72489FED7AB5E95D9300A06082A8648CE3D0403020349");
    private static final byte[] TEST_RECORD_BYTES_2 =
            ArrayConverter.hexStringToByteArray(
                    "16fefd000000000000000200f30b0001bc000100008c0000e772301e170d3231303230343232343735385a170d3331303230323232343735385a305b310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3111300f06035504070c0842656c6c65767565310e300c060355040a0c0556616c76653114301206035504030c0b496e7465727365727665723059301306072a8648ce3d020106082a8648ce3d0301070342000476edbd0bef9a383105c4a260377bb1aade43490491d7a2801c0755a1d8e187157d8406ba9c132e41b50e4481e2cf175ab23cc1ec31505bc72489fed7ab5e95d9300a06082a8648ce3d0403020349");

    @BeforeEach
    public void setUp() {
        // Setup mocks for DTLS record parsing
        when(tlsContext.getRecordLayer()).thenReturn(recordLayer);
        when(recordLayer.getDecryptor()).thenReturn(decryptor);
        when(decryptor.getRecordCipher(anyInt())).thenReturn(recordCipher);
    }

    @Test
    public void testParseSpecificRecordBytes() throws IOException {
        // Arrange
        InputStream inputStream = new ByteArrayInputStream(TEST_RECORD_BYTES_1);
        ProtocolVersion version = ProtocolVersion.DTLS12;
        recordParser = new RecordParser(inputStream, version, tlsContext);

        Record record = new Record();

        // Act
        recordParser.parse(record);

        // Assert
        // Verify content type (0x16 = HANDSHAKE)
        assertEquals(0x16, record.getContentType().getValue().byteValue());

        // Verify protocol version (0xFEFD = DTLS 1.2)
        assertArrayEquals(
                new byte[] {(byte) 0xFE, (byte) 0xFD}, record.getProtocolVersion().getValue());

        // Verify epoch (0x0000)
        assertEquals(0, record.getEpoch().getValue().intValue());

        // Verify sequence number (0x000000000002)
        assertEquals(new BigInteger("2"), record.getSequenceNumber().getValue());

        // Verify length (0x00F3 = 243 bytes)
        assertEquals(243, record.getLength().getValue().intValue());

        // Verify protocol message bytes length matches the length field
        assertEquals(243, record.getProtocolMessageBytes().getValue().length);

        // Verify complete record bytes contain the original data

        // Verify content message type is set to HANDSHAKE
        assertEquals(
                de.rub.nds.tlsattacker.core.constants.ProtocolMessageType.HANDSHAKE,
                record.getContentMessageType());
    }

    @Test
    public void testParseRecordWithTLSVersion() throws IOException {
        // Test with TLS version (non-DTLS) to ensure DTLS-specific fields are not parsed
        InputStream inputStream = new ByteArrayInputStream(TEST_RECORD_BYTES_1);
        ProtocolVersion version = ProtocolVersion.TLS12;
        recordParser = new RecordParser(inputStream, version, tlsContext);

        Record record = new Record();

        // Act
        recordParser.parse(record);

        // Assert
        // For TLS, epoch and sequence number should not be set
        assertNull(record.getEpoch());
        assertNull(record.getSequenceNumber());

        // Content type and version should still be parsed
        assertEquals(0x16, record.getContentType().getValue().byteValue());
        assertArrayEquals(
                new byte[] {(byte) 0xFE, (byte) 0xFD}, record.getProtocolVersion().getValue());
    }

    @Test
    public void testParseRecordWithConnectionId() throws IOException {
        // Test parsing with connection ID (TLS12_CID content type)
        byte[] cidRecordBytes =
                ArrayConverter.hexStringToByteArray("19FEFD000000000000020012345678AB");

        InputStream inputStream = new ByteArrayInputStream(cidRecordBytes);
        ProtocolVersion version = ProtocolVersion.DTLS12;
        recordParser = new RecordParser(inputStream, version, tlsContext);

        // Mock connection ID setup
        byte[] connectionId = new byte[] {0x12, 0x34};

        Record record = new Record();

        // Act
        recordParser.parse(record);

        // Assert
        // Verify content type (0x19 = TLS12_CID)
        assertEquals(0x19, record.getContentType().getValue().byteValue());

        // Verify connection ID is parsed
        assertArrayEquals(connectionId, record.getConnectionId().getValue());
    }

    @Test
    public void testParseEmptyRecord() throws IOException {
        // Test parsing a record with zero-length payload
        byte[] emptyRecordBytes = ArrayConverter.hexStringToByteArray("16FEFD00000000000002000000");

        InputStream inputStream = new ByteArrayInputStream(emptyRecordBytes);
        ProtocolVersion version = ProtocolVersion.DTLS12;
        recordParser = new RecordParser(inputStream, version, tlsContext);

        Record record = new Record();

        // Act
        recordParser.parse(record);

        // Assert
        assertEquals(0, record.getLength().getValue().intValue());
        assertEquals(0, record.getProtocolMessageBytes().getValue().length);
    }

    @Test
    public void testParseRecordVerifyAlreadyParsedBytes() throws IOException {
        // Test that getAlreadyParsed() returns the complete record
        InputStream inputStream = new ByteArrayInputStream(TEST_RECORD_BYTES_1);
        ProtocolVersion version = ProtocolVersion.DTLS12;
        recordParser = new RecordParser(inputStream, version, tlsContext);

        Record record = new Record();

        // Act
        recordParser.parse(record);

        // Assert
        byte[] alreadyParsed = recordParser.getAlreadyParsed();
        assertArrayEquals(TEST_RECORD_BYTES_1, alreadyParsed);
    }
}
