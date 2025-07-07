/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.dtls.handler.DtlsRecordOrderHandler;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.IOException;
import java.math.BigInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class RecordReceiveHandlerTest {

    @Mock private RecordLayer mockRecordLayer;
    @Mock private Context mockContext;
    @Mock private Config mockConfig;
    @Mock private Chooser mockChooser;
    @Mock private TlsContext mockTlsContext;
    @Mock private State mockState;
    @Mock private DtlsRecordOrderHandler mockDtlsRecordOrderHandler;

    private RecordReceiveHandler handler;
    private byte[] testData1;
    private byte[] testData2;
    private byte[] testData3;

    @BeforeEach
    public void setUp() {
        testData1 = new byte[] {1, 2, 3, 4, 5};
        testData2 = new byte[] {6, 7, 8, 9, 10};
        testData3 = new byte[] {11, 12, 13, 14, 15};

        // Setup basic mocks
        when(mockRecordLayer.getContext()).thenReturn(mockContext);
        when(mockContext.getChooser()).thenReturn(mockChooser);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockContext.getTlsContext()).thenReturn(mockTlsContext);

        handler = new RecordReceiveHandler(mockRecordLayer);
    }

    private Record createRecord(
            ProtocolMessageType messageType, int epoch, int sequenceNumber, byte[] data) {
        Record record = new Record();
        record.setContentMessageType(messageType);
        record.setEpoch(epoch);
        record.setSequenceNumber(BigInteger.valueOf(sequenceNumber));
        record.setCleanProtocolMessageBytes(data);
        return record;
    }

    // Constructor Tests
    @Test
    public void testConstructor() {
        RecordReceiveHandler testHandler = new RecordReceiveHandler(mockRecordLayer);
        assertNotNull(testHandler);
        assertEquals(mockRecordLayer, testHandler.getRecordLayer());
        assertNotNull(testHandler.getDtlsRecordOrderHandler());
        assertEquals(0, testHandler.getLastObservedEpoch());
        assertEquals(-1, testHandler.getLastSequenceNumber());
    }

    // Basic getter/setter tests
    @Test
    public void testGetSetLastObservedEpoch() {
        assertEquals(0, handler.getLastObservedEpoch());
        handler.setLastObservedEpoch(5);
        assertEquals(5, handler.getLastObservedEpoch());
    }

    @Test
    public void testGetSetLastSequenceNumber() {
        assertEquals(-1, handler.getLastSequenceNumber());
        handler.setLastSequenceNumber(10);
        assertEquals(10, handler.getLastSequenceNumber());
    }

    @Test
    public void testGetRecordLayer() {
        assertEquals(mockRecordLayer, handler.getRecordLayer());
    }

    @Test
    public void testGetDtlsRecordOrderHandler() {
        assertNotNull(handler.getDtlsRecordOrderHandler());
    }

    // TLS (non-DTLS) Tests
    @Test
    public void testReceiveNextRelevantRecordTlsWithoutHint() throws IOException {
        // Setup TLS context
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.TLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(false);

        Record testRecord = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        when(mockRecordLayer.parseNextRecord()).thenReturn(testRecord);

        Record result = handler.receiveNextRelevantRecord(null);

        assertNotNull(result);
        assertEquals(testRecord, result);
        verify(mockRecordLayer).extendCurrentStream(any(RecordLayerHint.class), eq(testData1));
        verify(mockRecordLayer, never()).extendNextStream(any(), any());
    }

    @Test
    public void testReceiveNextRelevantRecordTlsWithMatchingHint() throws IOException {
        // Setup TLS context
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.TLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(false);

        Record testRecord = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        when(mockRecordLayer.parseNextRecord()).thenReturn(testRecord);

        RecordLayerHint desiredHint = new RecordLayerHint(ProtocolMessageType.HANDSHAKE);
        Record result = handler.receiveNextRelevantRecord(desiredHint);

        assertNotNull(result);
        assertEquals(testRecord, result);
        verify(mockRecordLayer).extendCurrentStream(any(RecordLayerHint.class), eq(testData1));
        verify(mockRecordLayer, never()).extendNextStream(any(), any());
    }

    @Test
    public void testReceiveNextRelevantRecordTlsWithNonMatchingHint() throws IOException {
        // Setup TLS context
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.TLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(false);

        Record alertRecord = createRecord(ProtocolMessageType.ALERT, 0, 0, testData1);
        Record handshakeRecord = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData2);
        when(mockRecordLayer.parseNextRecord()).thenReturn(alertRecord, handshakeRecord);

        RecordLayerHint desiredHint = new RecordLayerHint(ProtocolMessageType.HANDSHAKE);
        Record result = handler.receiveNextRelevantRecord(desiredHint);

        assertNotNull(result);
        assertEquals(handshakeRecord, result);
        verify(mockRecordLayer).extendNextStream(any(RecordLayerHint.class), eq(testData1));
        verify(mockRecordLayer).extendCurrentStream(any(RecordLayerHint.class), eq(testData2));
    }

    // DTLS without reordering Tests
    @Test
    public void testReceiveNextRelevantRecordDtlsWithoutReordering() throws IOException {
        // Setup DTLS context without reordering
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(false);

        Record testRecord = createRecord(ProtocolMessageType.HANDSHAKE, 1, 5, testData1);
        when(mockRecordLayer.parseNextRecord()).thenReturn(testRecord);

        Record result = handler.receiveNextRelevantRecord(null);

        assertNotNull(result);
        assertEquals(testRecord, result);
        assertEquals(1, handler.getLastObservedEpoch());
        assertEquals(5, handler.getLastSequenceNumber());
        verify(mockRecordLayer).extendCurrentStream(any(RecordLayerHint.class), eq(testData1));
    }

    // DTLS with reordering Tests
    @Test
    public void testReceiveNextRelevantRecordDtlsWithReorderingFromQueue() throws IOException {
        // Setup DTLS context with reordering
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(true);

        // Replace the real DtlsRecordOrderHandler with a mock
        handler = spy(new RecordReceiveHandler(mockRecordLayer));
        when(handler.getDtlsRecordOrderHandler()).thenReturn(mockDtlsRecordOrderHandler);

        Record testRecord = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        when(mockDtlsRecordOrderHandler.getNextOrderConformingRecord(0, -1)).thenReturn(testRecord);

        Record result = handler.receiveNextRelevantRecord(null);

        assertNotNull(result);
        assertEquals(testRecord, result);
        assertEquals(0, handler.getLastObservedEpoch());
        assertEquals(0, handler.getLastSequenceNumber());
        verify(mockRecordLayer, never()).parseNextRecord();
    }

    @Test
    public void testReceiveNextRelevantRecordDtlsWithReorderingParseNew() throws IOException {
        // Setup DTLS context with reordering
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(true);

        // Replace the real DtlsRecordOrderHandler with a mock
        handler = spy(new RecordReceiveHandler(mockRecordLayer));
        when(handler.getDtlsRecordOrderHandler()).thenReturn(mockDtlsRecordOrderHandler);

        Record testRecord = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        when(mockDtlsRecordOrderHandler.getNextOrderConformingRecord(0, -1))
                .thenReturn(null, testRecord);
        when(mockRecordLayer.parseNextRecord()).thenReturn(testRecord);

        Record result = handler.receiveNextRelevantRecord(null);

        assertNotNull(result);
        assertEquals(testRecord, result);
        assertEquals(0, handler.getLastObservedEpoch());
        assertEquals(0, handler.getLastSequenceNumber());
        verify(mockRecordLayer).parseNextRecord();
        verify(mockDtlsRecordOrderHandler).addRecord(testRecord);
    }

    // canDrainOrderedDtlsRecords Tests
    @Test
    public void testCanDrainOrderedDtlsRecordsTlsProtocol() {
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.TLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(true);

        assertFalse(handler.canDrainOrderedDtlsRecords());
    }

    @Test
    public void testCanDrainOrderedDtlsRecordsDtlsWithoutReordering() {
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(false);

        assertFalse(handler.canDrainOrderedDtlsRecords());
    }

    @Test
    public void testCanDrainOrderedDtlsRecordsDtlsWithReorderingTrue() {
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(true);

        // Replace the real DtlsRecordOrderHandler with a mock
        handler = spy(new RecordReceiveHandler(mockRecordLayer));
        when(handler.getDtlsRecordOrderHandler()).thenReturn(mockDtlsRecordOrderHandler);
        when(mockDtlsRecordOrderHandler.drainable(-1, 0)).thenReturn(true);

        assertTrue(handler.canDrainOrderedDtlsRecords());
        verify(mockDtlsRecordOrderHandler).drainable(-1, 0);
    }

    @Test
    public void testCanDrainOrderedDtlsRecordsDtlsWithReorderingFalse() {
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(true);

        // Replace the real DtlsRecordOrderHandler with a mock
        handler = spy(new RecordReceiveHandler(mockRecordLayer));
        when(handler.getDtlsRecordOrderHandler()).thenReturn(mockDtlsRecordOrderHandler);
        when(mockDtlsRecordOrderHandler.drainable(-1, 0)).thenReturn(false);

        assertFalse(handler.canDrainOrderedDtlsRecords());
        verify(mockDtlsRecordOrderHandler).drainable(-1, 0);
    }

    // Integration Tests
    @Test
    public void testDtlsRecordOrderingIntegration() throws IOException {
        // Setup DTLS context with reordering
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(true);

        // Use real DtlsRecordOrderHandler for integration test
        Record record0 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, testData2);
        Record record2 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 2, testData3);

        // Simulate receiving records out of order
        when(mockRecordLayer.parseNextRecord()).thenReturn(record2, record0, record1);

        // First call should return record0 (sequence 0)
        Record result1 = handler.receiveNextRelevantRecord(null);
        assertEquals(record0, result1);
        assertEquals(0, handler.getLastObservedEpoch());
        assertEquals(0, handler.getLastSequenceNumber());

        // Second call should return record1 (sequence 1)
        Record result2 = handler.receiveNextRelevantRecord(null);
        assertEquals(record1, result2);
        assertEquals(0, handler.getLastObservedEpoch());
        assertEquals(1, handler.getLastSequenceNumber());

        // Third call should return record2 (sequence 2)
        Record result3 = handler.receiveNextRelevantRecord(null);
        assertEquals(record2, result3);
        assertEquals(0, handler.getLastObservedEpoch());
        assertEquals(2, handler.getLastSequenceNumber());
    }

    @Test
    public void testDtlsEpochTransition() throws IOException {
        // Setup DTLS context with reordering
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(true);

        // Create records for epoch transition
        Record lastRecordEpoch0 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 2, testData1);
        Record firstRecordEpoch1 = createRecord(ProtocolMessageType.HANDSHAKE, 1, 0, testData2);

        when(mockRecordLayer.parseNextRecord()).thenReturn(lastRecordEpoch0, firstRecordEpoch1);

        // Set initial state
        handler.setLastObservedEpoch(0);
        handler.setLastSequenceNumber(1);

        // First call should return last record of epoch 0
        Record result1 = handler.receiveNextRelevantRecord(null);
        assertEquals(lastRecordEpoch0, result1);
        assertEquals(0, handler.getLastObservedEpoch());
        assertEquals(2, handler.getLastSequenceNumber());

        // Second call should return first record of epoch 1
        Record result2 = handler.receiveNextRelevantRecord(null);
        assertEquals(firstRecordEpoch1, result2);
        assertEquals(1, handler.getLastObservedEpoch());
        assertEquals(0, handler.getLastSequenceNumber());
    }

    @Test
    public void testComplexDtlsHintMatching() throws IOException {
        // Setup DTLS context with reordering
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(true);

        Record alertRecord = createRecord(ProtocolMessageType.ALERT, 0, 0, testData1);
        Record handshakeRecord = createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, testData2);

        when(mockRecordLayer.parseNextRecord()).thenReturn(alertRecord, handshakeRecord);

        RecordLayerHint desiredHint = new RecordLayerHint(ProtocolMessageType.HANDSHAKE, 0, 1);
        Record result = handler.receiveNextRelevantRecord(desiredHint);

        assertEquals(handshakeRecord, result);
        assertEquals(0, handler.getLastObservedEpoch());
        assertEquals(1, handler.getLastSequenceNumber());
        verify(mockRecordLayer).extendNextStream(any(RecordLayerHint.class), eq(testData1));
        verify(mockRecordLayer).extendCurrentStream(any(RecordLayerHint.class), eq(testData2));
    }

    // Error handling tests
    @Test
    public void testReceiveNextRelevantRecordIOException() throws IOException {
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.TLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(false);
        when(mockRecordLayer.parseNextRecord()).thenThrow(new IOException("Test exception"));

        assertThrows(IOException.class, () -> handler.receiveNextRelevantRecord(null));
    }

    @Test
    public void testStatePersistence() throws IOException {
        // Test that epoch and sequence number state is properly maintained
        when(mockChooser.getSelectedProtocolVersion()).thenReturn(ProtocolVersion.DTLS12);
        when(mockConfig.getReorderReceivedDtlsRecords()).thenReturn(false);

        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 2, 10, testData1);
        Record record2 = createRecord(ProtocolMessageType.HANDSHAKE, 3, 5, testData2);

        when(mockRecordLayer.parseNextRecord()).thenReturn(record1, record2);

        // First record
        handler.receiveNextRelevantRecord(null);
        assertEquals(2, handler.getLastObservedEpoch());
        assertEquals(10, handler.getLastSequenceNumber());

        // Second record
        handler.receiveNextRelevantRecord(null);
        assertEquals(3, handler.getLastObservedEpoch());
        assertEquals(5, handler.getLastSequenceNumber());
    }
}
