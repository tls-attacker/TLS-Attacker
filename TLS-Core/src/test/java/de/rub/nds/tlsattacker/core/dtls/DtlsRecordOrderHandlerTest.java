/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.dtls.handler.DtlsRecordOrderHandler;
import de.rub.nds.tlsattacker.core.record.Record;
import java.math.BigInteger;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

public class DtlsRecordOrderHandlerTest {

    private DtlsRecordOrderHandler handler;
    private byte[] testData1;
    private byte[] testData2;
    private byte[] testData3;

    @BeforeEach
    public void setUp() {
        handler = new DtlsRecordOrderHandler();
        testData1 = new byte[] {1, 2, 3, 4, 5};
        testData2 = new byte[] {6, 7, 8, 9, 10};
        testData3 = new byte[] {11, 12, 13, 14, 15};
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
        DtlsRecordOrderHandler newHandler = new DtlsRecordOrderHandler();
        assertTrue(newHandler.isEmpty());
        assertEquals(0, newHandler.size());
    }

    // Basic functionality tests
    @Test
    public void testAddRecord() {
        Record record = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);

        handler.addRecord(record);

        assertEquals(1, handler.size());
        assertFalse(handler.isEmpty());
    }

    @Test
    public void testAddRecordNull() {
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> handler.addRecord(null));
        assertEquals("Record cannot be null", exception.getMessage());
    }

    @Test
    public void testAddRecordNullEpoch() {
        Record record = new Record();
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setSequenceNumber(BigInteger.valueOf(0));
        record.setCleanProtocolMessageBytes(testData1);

        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> handler.addRecord(record));
        assertEquals("Record epoch must be set", exception.getMessage());
    }

    @Test
    public void testAddRecordNullSequenceNumber() {
        Record record = new Record();
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setEpoch(0);
        record.setCleanProtocolMessageBytes(testData1);

        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> handler.addRecord(record));
        assertEquals("Record sequence number must be set", exception.getMessage());
    }

    // Order conforming tests - same epoch
    @Test
    public void testHasOrderConformingRecordSameEpochNextSequence() {
        Record record = createRecord(ProtocolMessageType.HANDSHAKE, 0, 5, testData1);
        handler.addRecord(record);

        assertTrue(handler.hasOrderConformingRecord(0, 4));
        assertFalse(handler.hasOrderConformingRecord(0, 5));
        assertFalse(handler.hasOrderConformingRecord(0, 3));
    }

    @Test
    public void testHasOrderConformingRecordNewEpochZeroSequence() {
        Record record = createRecord(ProtocolMessageType.HANDSHAKE, 1, 0, testData1);
        handler.addRecord(record);

        assertTrue(
                handler.hasOrderConformingRecord(0, 999)); // Any sequence number in previous epoch
        assertFalse(handler.hasOrderConformingRecord(1, 0));
        assertFalse(handler.hasOrderConformingRecord(2, 0));
    }

    @Test
    public void testHasOrderConformingRecordEmptyQueue() {
        assertFalse(handler.hasOrderConformingRecord(0, 0));
        assertFalse(handler.hasOrderConformingRecord(1, 5));
    }

    @Test
    public void testHasOrderConformingRecordNonConformingRecord() {
        Record record = createRecord(ProtocolMessageType.HANDSHAKE, 0, 10, testData1);
        handler.addRecord(record);

        assertFalse(handler.hasOrderConformingRecord(0, 8)); // Gap in sequence
        assertFalse(handler.hasOrderConformingRecord(1, 0)); // Wrong epoch
    }

    // Get conforming record tests
    @Test
    public void testGetNextOrderConformingRecordSameEpoch() {
        Record record = createRecord(ProtocolMessageType.HANDSHAKE, 0, 5, testData1);
        handler.addRecord(record);

        Record retrievedRecord = handler.getNextOrderConformingRecord(0, 4);
        assertNotNull(retrievedRecord);
        assertEquals(0, retrievedRecord.getEpoch().getValue().intValue());
        assertEquals(5, retrievedRecord.getSequenceNumber().getValue().intValue());
        assertArrayEquals(testData1, retrievedRecord.getCleanProtocolMessageBytes().getValue());

        // Record should be removed from queue
        assertEquals(0, handler.size());
        assertTrue(handler.isEmpty());
    }

    @Test
    public void testGetNextOrderConformingRecordNewEpoch() {
        Record record = createRecord(ProtocolMessageType.HANDSHAKE, 1, 0, testData1);
        handler.addRecord(record);

        Record retrievedRecord = handler.getNextOrderConformingRecord(0, 999);
        assertNotNull(retrievedRecord);
        assertEquals(1, retrievedRecord.getEpoch().getValue().intValue());
        assertEquals(0, retrievedRecord.getSequenceNumber().getValue().intValue());
        assertArrayEquals(testData1, retrievedRecord.getCleanProtocolMessageBytes().getValue());

        // Record should be removed from queue
        assertEquals(0, handler.size());
    }

    @Test
    public void testGetNextOrderConformingRecordEmptyQueue() {
        assertNull(handler.getNextOrderConformingRecord(0, 0));
    }

    @Test
    public void testGetNextOrderConformingRecordNonConforming() {
        Record record = createRecord(ProtocolMessageType.HANDSHAKE, 0, 10, testData1);
        handler.addRecord(record);

        assertNull(handler.getNextOrderConformingRecord(0, 8));

        // Record should still be in queue
        assertEquals(1, handler.size());
        assertFalse(handler.isEmpty());
    }

    // Priority queue ordering tests
    @Test
    public void testRecordOrderingByEpoch() {
        // Add records with different epochs out of order
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 2, 0, testData3));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 1, 0, testData2));

        assertEquals(3, handler.size());

        // Should get records in epoch order
        Record record1 = handler.getNextOrderConformingRecord(-1, -1); // Start from beginning
        assertNotNull(record1);
        assertEquals(0, record1.getEpoch().getValue().intValue());

        Record record2 = handler.getNextOrderConformingRecord(0, 0);
        assertNotNull(record2);
        assertEquals(1, record2.getEpoch().getValue().intValue());

        Record record3 = handler.getNextOrderConformingRecord(1, 0);
        assertNotNull(record3);
        assertEquals(2, record3.getEpoch().getValue().intValue());
    }

    @Test
    public void testRecordOrderingBySequenceNumber() {
        // Add records with same epoch but different sequence numbers out of order
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 3, testData3));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, testData1));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 2, testData2));

        assertEquals(3, handler.size());

        // Should get records in sequence number order within same epoch
        Record record1 = handler.getNextOrderConformingRecord(0, 0);
        assertNotNull(record1);
        assertEquals(1, record1.getSequenceNumber().getValue().intValue());

        Record record2 = handler.getNextOrderConformingRecord(0, 1);
        assertNotNull(record2);
        assertEquals(2, record2.getSequenceNumber().getValue().intValue());

        Record record3 = handler.getNextOrderConformingRecord(0, 2);
        assertNotNull(record3);
        assertEquals(3, record3.getSequenceNumber().getValue().intValue());
    }

    @Test
    public void testComplexOrderingScenario() {
        // Mix of epochs and sequence numbers
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 1, 1, new byte[] {11}));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 2, new byte[] {02}));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 1, 0, new byte[] {10}));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, new byte[] {01}));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, new byte[] {00}));

        assertEquals(5, handler.size());

        // Process in correct order
        int[] expectedEpochs = {0, 0, 0, 1, 1};
        int[] expectedSeqNums = {0, 1, 2, 0, 1};
        byte[] expectedFirstBytes = {00, 01, 02, 10, 11};

        int lastEpoch = -1;
        int lastSeqNum = -1;

        for (int i = 0; i < 5; i++) {
            assertTrue(handler.hasOrderConformingRecord(lastEpoch, lastSeqNum));
            Record record = handler.getNextOrderConformingRecord(lastEpoch, lastSeqNum);
            assertNotNull(record);
            assertEquals(expectedEpochs[i], record.getEpoch().getValue().intValue());
            assertEquals(expectedSeqNums[i], record.getSequenceNumber().getValue().intValue());
            assertEquals(
                    expectedFirstBytes[i], record.getCleanProtocolMessageBytes().getValue()[0]);

            lastEpoch = record.getEpoch().getValue();
            lastSeqNum = record.getSequenceNumber().getValue().intValue();
        }

        assertTrue(handler.isEmpty());
    }

    // Utility method tests
    @Test
    public void testSize() {
        assertEquals(0, handler.size());

        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1));
        assertEquals(1, handler.size());

        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, testData2));
        assertEquals(2, handler.size());

        handler.getNextOrderConformingRecord(-1, -1);
        assertEquals(1, handler.size());
    }

    @Test
    public void testIsEmpty() {
        assertTrue(handler.isEmpty());

        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1));
        assertFalse(handler.isEmpty());

        handler.clear();
        assertTrue(handler.isEmpty());
    }

    @Test
    public void testClear() {
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, testData2));

        assertEquals(2, handler.size());
        assertFalse(handler.isEmpty());

        handler.clear();

        assertEquals(0, handler.size());
        assertTrue(handler.isEmpty());
        assertFalse(handler.hasOrderConformingRecord(0, 0));
    }

    // Edge case tests
    @Test
    public void testSequenceNumberWrapAround() {
        // Test behavior with large sequence numbers (near integer overflow)
        int maxSeqNum = Integer.MAX_VALUE;
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, maxSeqNum, testData1));

        assertFalse(handler.hasOrderConformingRecord(0, maxSeqNum - 2));
        assertTrue(handler.hasOrderConformingRecord(0, maxSeqNum - 1));
    }

    @Test
    public void testMultipleRecordsWithSameEpochAndSequence() {
        // Technically shouldn't happen in DTLS, but test handling
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        Record record2 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData2);

        handler.addRecord(record1);
        handler.addRecord(record2); // Same epoch and sequence

        assertEquals(2, handler.size());

        // Should be able to get both records (priority queue allows duplicates)
        Record retrievedRecord1 = handler.getNextOrderConformingRecord(-1, -1);
        assertNotNull(retrievedRecord1);

        Record retrievedRecord2 = handler.getNextOrderConformingRecord(-1, -1);
        assertNotNull(retrievedRecord2);

        assertTrue(handler.isEmpty());
    }

    @Test
    public void testGapInSequenceNumbers() {
        // Add records with gaps in sequence numbers
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1));
        handler.addRecord(
                createRecord(ProtocolMessageType.HANDSHAKE, 0, 2, testData2)); // Gap at sequence 1
        handler.addRecord(
                createRecord(
                        ProtocolMessageType.HANDSHAKE, 0, 5, testData3)); // Gap at sequences 3,4

        // Should be able to get first record
        assertTrue(handler.hasOrderConformingRecord(-1, -1));
        Record record1 = handler.getNextOrderConformingRecord(-1, -1);
        assertEquals(0, record1.getSequenceNumber().getValue().intValue());

        // Should not be able to get record with sequence 2 (gap at sequence 1)
        assertFalse(handler.hasOrderConformingRecord(0, 0));
        assertNull(handler.getNextOrderConformingRecord(0, 0));

        // Still have 2 records in queue
        assertEquals(2, handler.size());
    }

    // Thread safety tests
    @Test
    @Timeout(5)
    public void testConcurrentAddRecord() throws InterruptedException {
        final int threadCount = 10;
        final int recordsPerThread = 100;
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch endLatch = new CountDownLatch(threadCount);

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(
                    () -> {
                        try {
                            startLatch.await();
                            for (int i = 0; i < recordsPerThread; i++) {
                                Record record =
                                        createRecord(
                                                ProtocolMessageType.HANDSHAKE,
                                                threadId,
                                                i,
                                                new byte[] {(byte) threadId, (byte) i});
                                handler.addRecord(record);
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } finally {
                            endLatch.countDown();
                        }
                    });
        }

        startLatch.countDown(); // Start all threads
        endLatch.await(3, TimeUnit.SECONDS); // Wait for completion
        executor.shutdown();

        assertEquals(threadCount * recordsPerThread, handler.size());
    }

    // Integration test simulating real DTLS usage
    @Test
    public void testDtlsUsageScenario() {
        // Simulate a realistic DTLS scenario with out-of-order delivery

        // Epoch 0: Initial handshake
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 2, new byte[] {0, 2}));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, new byte[] {0, 0}));
        handler.addRecord(createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, new byte[] {0, 1}));

        // Epoch 1: After ChangeCipherSpec
        handler.addRecord(
                createRecord(ProtocolMessageType.APPLICATION_DATA, 1, 1, new byte[] {1, 1}));
        handler.addRecord(
                createRecord(ProtocolMessageType.APPLICATION_DATA, 1, 0, new byte[] {1, 0}));

        assertEquals(5, handler.size());

        // Process records in order
        int lastEpoch = -1;
        int lastSeqNum = -1;
        int recordCount = 0;

        while (handler.hasOrderConformingRecord(lastEpoch, lastSeqNum)) {
            Record record = handler.getNextOrderConformingRecord(lastEpoch, lastSeqNum);
            assertNotNull(record);

            // Verify the record is the expected next one
            byte[] data = record.getCleanProtocolMessageBytes().getValue();
            assertEquals(record.getEpoch().getValue().byteValue(), data[0]);
            assertEquals(record.getSequenceNumber().getValue().byteValue(), data[1]);

            lastEpoch = record.getEpoch().getValue();
            lastSeqNum = record.getSequenceNumber().getValue().intValue();
            recordCount++;
        }

        assertEquals(5, recordCount);
        assertTrue(handler.isEmpty());
    }

    // Drainable tests
    @Test
    public void testDrainableEmptyQueue() {
        // Empty queue should return false
        assertFalse(handler.drainable(0, 0));
        assertFalse(handler.drainable(1, 0));
        assertFalse(handler.drainable(5, 10));
    }

    @Test
    public void testDrainableWithSingleRecord() {
        Record record = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        handler.addRecord(record);

        // Should be drainable if starting from correct position
        assertTrue(handler.drainable(-1, 0));

        // Should not be drainable if starting from wrong position
        assertFalse(handler.drainable(0, 0));
        assertFalse(handler.drainable(1, 0));
        assertFalse(handler.drainable(5, 10));
    }

    @Test
    public void testDrainableWithSequentialRecords() {
        // Add records in order
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        Record record2 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, testData2);
        Record record3 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 2, testData3);

        handler.addRecord(record1);
        handler.addRecord(record2);
        handler.addRecord(record3);

        // Should be drainable from start
        assertTrue(handler.drainable(-1, 0));

        // Should not be drainable from wrong position
        assertFalse(handler.drainable(3, 0));
        assertFalse(handler.drainable(0, 5));
    }

    @Test
    public void testDrainableWithOutOfOrderRecords() {
        // Add records out of order
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 2, testData1);
        Record record2 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData2);
        Record record3 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, testData3);

        handler.addRecord(record1);
        handler.addRecord(record2);
        handler.addRecord(record3);

        // Should be drainable as all records are present
        assertTrue(handler.drainable(-1, 0));

        // Should not be drainable from wrong position
        assertFalse(handler.drainable(3, 0));
    }

    @Test
    public void testDrainableWithGapInSequence() {
        // Add records with gap in sequence
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        Record record2 =
                createRecord(ProtocolMessageType.HANDSHAKE, 0, 2, testData2); // Gap at seq 1
        Record record3 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 3, testData3);

        handler.addRecord(record1);
        handler.addRecord(record2);
        handler.addRecord(record3);

        // Should not be drainable due to gap
        assertFalse(handler.drainable(-1, 0));
        assertFalse(handler.drainable(0, 0));

        // Should not be drainable from position that skips the gap
        assertFalse(handler.drainable(1, 0));
    }

    @Test
    public void testDrainableWithMultipleEpochs() {
        // Add records across different epochs
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        Record record2 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, testData2);
        Record record3 = createRecord(ProtocolMessageType.HANDSHAKE, 1, 0, testData3); // New epoch

        handler.addRecord(record1);
        handler.addRecord(record2);
        handler.addRecord(record3);

        // Should be drainable from start
        assertTrue(handler.drainable(-1, 0));

        // Should not be drainable from wrong epoch transition
        assertFalse(handler.drainable(0, 1));
        assertFalse(handler.drainable(2, 0));
    }

    @Test
    public void testDrainableWithEpochGap() {
        // Add records with gap in epoch
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        Record record2 =
                createRecord(ProtocolMessageType.HANDSHAKE, 2, 0, testData2); // Gap at epoch 1

        handler.addRecord(record1);
        handler.addRecord(record2);

        // Should not be drainable due to epoch gap
        assertFalse(handler.drainable(-1, 0));
        assertFalse(handler.drainable(0, 0));

        // Should not be drainable from position that skips the gap
        assertFalse(handler.drainable(-1, 2));
    }

    @Test
    public void testDrainableRestoresOriginalQueue() {
        // Add records
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 0, testData1);
        Record record2 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 1, testData2);

        handler.addRecord(record1);
        handler.addRecord(record2);

        int originalSize = handler.size();

        // Call drainable
        boolean result = handler.drainable(-1, 0);

        // Queue should be restored to original state
        assertEquals(originalSize, handler.size());
        assertTrue(result);

        // Should still be able to retrieve records normally
        assertTrue(handler.hasOrderConformingRecord(-1, 0));
        Record retrieved = handler.getNextOrderConformingRecord(-1, 0);
        assertNotNull(retrieved);
        assertEquals(0, retrieved.getEpoch().getValue().intValue());
        assertEquals(0, retrieved.getSequenceNumber().getValue().intValue());
    }

    @Test
    public void testDrainableWithComplexScenario() {
        // Add records in complex out-of-order scenario
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 5, testData1);
        Record record2 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 3, testData2);
        Record record3 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 4, testData3);
        Record record4 = createRecord(ProtocolMessageType.HANDSHAKE, 1, 0, testData1);
        Record record5 = createRecord(ProtocolMessageType.HANDSHAKE, 0, 6, testData2);

        handler.addRecord(record1);
        handler.addRecord(record2);
        handler.addRecord(record3);
        handler.addRecord(record4);
        handler.addRecord(record5);

        // Should be drainable from correct starting position
        assertTrue(handler.drainable(2, 0));

        // Should not be drainable from positions that would leave gaps
        assertFalse(handler.drainable(-1, 0));
        assertFalse(handler.drainable(0, 0));
        assertFalse(handler.drainable(1, 0));
        assertFalse(handler.drainable(4, 0));
    }

    @Test
    public void testDrainableWithHighSequenceNumbers() {
        // Test with high sequence numbers to ensure no overflow issues
        Record record1 = createRecord(ProtocolMessageType.HANDSHAKE, 5, 1000, testData1);
        Record record2 = createRecord(ProtocolMessageType.HANDSHAKE, 5, 1001, testData2);
        Record record3 = createRecord(ProtocolMessageType.HANDSHAKE, 5, 1002, testData3);

        handler.addRecord(record1);
        handler.addRecord(record2);
        handler.addRecord(record3);

        // Should be drainable from correct starting position
        assertTrue(handler.drainable(999, 5));

        // Should not be drainable from wrong position
        assertFalse(handler.drainable(1003, 5));
        assertFalse(handler.drainable(999, 4));
    }
}
