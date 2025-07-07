/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls.handler;

import de.rub.nds.tlsattacker.core.record.Record;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.PriorityQueue;

/**
 * Provides functionality to retrieve DTLS records in order that conforms to the intended record
 * sequence (epoch and sequence number) of DTLS records.
 *
 * <p>This handler manages out-of-order DTLS records by maintaining an internal priority queue that
 * orders records first by epoch, then by sequence number within each epoch. It provides methods to
 * check for and retrieve records that conform to the expected ordering sequence.
 *
 * <p>In DTLS, records are uniquely identified by their epoch and sequence number combination:
 *
 * <ul>
 *   <li><strong>Epoch:</strong> A counter that increments when the cipher suite changes (e.g.,
 *       after ChangeCipherSpec). Each epoch starts with sequence number 0.
 *   <li><strong>Sequence Number:</strong> A counter that increments with each record sent within
 *       the same epoch. Resets to 0 when a new epoch begins.
 * </ul>
 *
 * <p>The expected ordering logic is:
 *
 * <ol>
 *   <li>Records within the same epoch must be processed in sequence number order
 *   <li>When transitioning to a new epoch, the sequence number resets to 0
 *   <li>A record is considered "next in order" if it has either:
 *       <ul>
 *         <li>The same epoch and sequence number = previous sequence number + 1, OR
 *         <li>Epoch = previous epoch + 1 and sequence number = 0
 *       </ul>
 * </ol>
 *
 * <p><strong>Thread Safety:</strong> This class is thread-safe for concurrent access to the {@link
 * #addRecord(Record)} method. Other methods should be called from the same thread that processes
 * records.
 *
 * <p><strong>Usage Example:</strong>
 *
 * <pre>{@code
 * DtlsRecordOrderHandler handler = new DtlsRecordOrderHandler();
 *
 * // Add records as they arrive (potentially out of order)
 * handler.addRecord(record1);
 * handler.addRecord(record0);
 *
 * // Process records in order
 * int lastEpoch = -1;
 * int lastSeqNum = -1;
 *
 * while (handler.hasOrderConformingRecord(lastEpoch, lastSeqNum)) {
 *     Record record = handler.getNextOrderConformingRecord(lastEpoch, lastSeqNum);
 *     lastEpoch = record.getEpoch().getValue();
 *     lastSeqNum = record.getSequenceNumber().getValue().intValue();
 *     // Process record...
 * }
 * }</pre>
 *
 * @see Record
 * @see de.rub.nds.tlsattacker.core.dtls.FragmentManager
 * @see de.rub.nds.tlsattacker.core.layer.impl.DtlsFragmentLayer
 */
public class DtlsRecordOrderHandler {

    /**
     * Internal priority queue that maintains records ordered by epoch first, then by sequence
     * number. Records are automatically sorted upon insertion to maintain proper DTLS ordering.
     */
    private PriorityQueue<Record> recordQueue;

    /**
     * Constructs a new DtlsRecordOrderHandler with an empty record queue.
     *
     * <p>The internal priority queue is initialized with a comparator that orders records by epoch
     * first, then by sequence number within each epoch, ensuring that records can be retrieved in
     * the correct DTLS processing order.
     */
    public DtlsRecordOrderHandler() {
        // Initialize the priority queue with a comparator that orders records by epoch first, then
        // by sequence number
        this.recordQueue =
                new PriorityQueue<>(
                        new Comparator<Record>() {
                            @Override
                            public int compare(Record r1, Record r2) {
                                // Compare by epoch first
                                Integer epoch1 =
                                        r1.getEpoch() != null ? r1.getEpoch().getValue() : 0;
                                Integer epoch2 =
                                        r2.getEpoch() != null ? r2.getEpoch().getValue() : 0;
                                int epochComparison = Integer.compare(epoch1, epoch2);
                                if (epochComparison != 0) {
                                    return epochComparison;
                                }

                                // If epochs are equal, compare by sequence number
                                BigInteger seqNum1 =
                                        r1.getSequenceNumber() != null
                                                ? r1.getSequenceNumber().getValue()
                                                : BigInteger.ZERO;
                                BigInteger seqNum2 =
                                        r2.getSequenceNumber() != null
                                                ? r2.getSequenceNumber().getValue()
                                                : BigInteger.ZERO;
                                return seqNum1.compareTo(seqNum2);
                            }
                        });
    }

    /**
     * Adds a record to the internal priority queue of the order handler.
     *
     * <p>The record is automatically positioned in the queue based on its epoch and sequence number
     * to maintain proper DTLS ordering. Records with lower epoch values are prioritized, and within
     * the same epoch, records with lower sequence numbers are prioritized.
     *
     * <p>This method is thread-safe and can be called concurrently from multiple threads.
     *
     * @param record The DTLS record to add. Must not be null and must have both epoch and sequence
     *     number set.
     * @throws IllegalArgumentException if record is null, or if the record does not contain both
     *     epoch and sequence number
     */
    public synchronized void addRecord(Record record) {
        if (record == null) {
            throw new IllegalArgumentException("Record cannot be null");
        }
        if (record.getEpoch() == null || record.getEpoch().getValue() == null) {
            throw new IllegalArgumentException("Record epoch must be set");
        }
        if (record.getSequenceNumber() == null || record.getSequenceNumber().getValue() == null) {
            throw new IllegalArgumentException("Record sequence number must be set");
        }

        recordQueue.offer(record);
    }

    /**
     * Checks whether a record was submitted to this handler that would be the next in the expected
     * DTLS ordering sequence after the given epoch and sequence number parameters.
     *
     * <p>A record is considered "next in order" if it satisfies one of the following conditions:
     *
     * <ol>
     *   <li>Same epoch and sequence number = lastSeqNum + 1 (normal sequence progression)
     *   <li>Epoch = lastEpoch + 1 and sequence number = 0 (new epoch beginning)
     * </ol>
     *
     * <p>This method only examines the head of the internal priority queue without removing it,
     * making it safe to call multiple times without affecting the queue state.
     *
     * @param lastEpoch The epoch of the previously processed record
     * @param lastSeqNum The sequence number of the previously processed record
     * @return {@code true} if there is a record that conforms to the expected ordering sequence,
     *     {@code false} if no such record exists in the queue or if the queue is empty
     * @see #getNextOrderConformingRecord(int, int)
     */
    public boolean hasOrderConformingRecord(int lastEpoch, int lastSeqNum) {
        if (recordQueue.isEmpty()) {
            return false;
        }

        Record head = recordQueue.peek();
        int headEpoch = head.getEpoch().getValue();
        int headSeqNum = head.getSequenceNumber().getValue().intValue();

        // Check if the head record is the next in sequence
        // Either: same epoch and next sequence number, OR next epoch and sequence number 0
        return (headEpoch == lastEpoch && headSeqNum == lastSeqNum + 1)
                || (headEpoch == lastEpoch + 1 && headSeqNum == 0);
    }

    /**
     * Returns and removes a record from this handler that would be the next in the expected DTLS
     * ordering sequence after the given epoch and sequence number parameters.
     *
     * <p>This method applies the same ordering logic as {@link #hasOrderConformingRecord(int, int)}
     * but additionally removes the conforming record from the internal queue if found.
     *
     * @param lastEpoch The epoch of the previously processed record
     * @param lastSeqNum The sequence number of the previously processed record
     * @return The next record in the ordering sequence, or {@code null} if no conforming record is
     *     found in the queue or if the queue is empty
     * @see #hasOrderConformingRecord(int, int)
     * @see Record
     */
    public Record getNextOrderConformingRecord(int lastEpoch, int lastSeqNum) {
        if (recordQueue.isEmpty()) {
            return null;
        }

        Record head = recordQueue.peek();
        int headEpoch = head.getEpoch().getValue();
        int headSeqNum = head.getSequenceNumber().getValue().intValue();

        // Check if the head record is the next in sequence
        // Either: same epoch and next sequence number, OR next epoch and sequence number 0
        if ((headEpoch == lastEpoch && headSeqNum == lastSeqNum + 1)
                || (headEpoch == lastEpoch + 1 && headSeqNum == 0)) {
            return recordQueue.poll(); // Remove and return the head
        }

        return null;
    }

    /**
     * Determines if all records in the queue can be drained in order starting from the specified
     * sequence number and epoch.
     *
     * <p>The method attempts to retrieve all records from the queue in order, based on the given
     * starting sequence number and epoch, to check if the queue can be completely emptied following
     * the correct order. If any records are found to be out of order or if the queue cannot be
     * entirely processed, the method returns false.
     *
     * <p>An empty queue will result in a return of false, as is it not drainable.
     *
     * @param startSequence The starting sequence number used to assess order conformity.
     * @param startEpoch The starting epoch used to assess order conformity.
     * @return {@code true} if the queue can be entirely drained in order beginning from the
     *     specified sequence number and epoch, {@code false} otherwise.
     */
    public boolean drainable(int startSequence, int startEpoch) {

        if (this.isEmpty()) {
            return false;
        }

        List<Record> storedRecords = new ArrayList<>();

        int lastTheoreticalEpoch = startEpoch;
        int lastTheoreticalSequenceNumber = startSequence;

        // has a look into the queue of the order handler if we are able reassemble them completely
        // in order
        while (this.hasOrderConformingRecord(lastTheoreticalEpoch, lastTheoreticalSequenceNumber)) {
            Record nextRecord =
                    this.getNextOrderConformingRecord(
                            lastTheoreticalEpoch, lastTheoreticalSequenceNumber);
            storedRecords.add(nextRecord);
            lastTheoreticalEpoch = nextRecord.getEpoch().getValue();
            lastTheoreticalSequenceNumber = nextRecord.getSequenceNumber().getValue().intValue();
        }

        int recordLeftInQueue = this.size();

        // put the records back into the queue
        storedRecords.forEach(this::addRecord);

        if (recordLeftInQueue > 0) {
            // record left, that we can not retrieve since out of order
            return false;
        }

        // managed to drain a non-empty queue with the current sequence and epoch as starting point
        return true;
    }

    /**
     * Returns the number of records currently stored in the internal queue.
     *
     * @return The number of records in the queue, 0 if the queue is empty
     */
    public int size() {
        return recordQueue.size();
    }

    /**
     * Removes all records from the internal queue.
     *
     * <p>After calling this method, the handler will be in the same state as a newly constructed
     * instance, with an empty queue ready to accept new records.
     */
    public void clear() {
        recordQueue.clear();
    }

    /**
     * Checks if the internal record queue is empty.
     *
     * @return {@code true} if the queue contains no records, {@code false} otherwise
     */
    public boolean isEmpty() {
        return recordQueue.isEmpty();
    }

    public Record peek() {
        return recordQueue.peek();
    }
}
