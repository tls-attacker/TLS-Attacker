/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record;

import de.rub.nds.tlsattacker.core.dtls.handler.DtlsRecordOrderHandler;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Helper class for the RecordLayer that will handle receiving data from the lower layer for the
 * desired hint but also maintain DTLS record order, if enabled.
 */
public class RecordReceiveHandler {

    private static final Logger LOGGER = LogManager.getLogger();

    private int lastObservedEpoch = 0;
    private int lastSequenceNumber = -1;

    private final RecordLayer recordLayer;
    private final DtlsRecordOrderHandler dtlsRecordOrderHandler;

    public RecordReceiveHandler(RecordLayer recordLayer) {
        this.recordLayer = recordLayer;
        this.dtlsRecordOrderHandler = new DtlsRecordOrderHandler();
    }

    /**
     * Retrieves the next relevant record based on the specified processing hint and the provided
     * record parser. This method ensures proper handling of DTLS record reordering if applicable
     * and processes records until the desired record is found.
     *
     * @param desiredHint The processing hint indicating the desired type or stream characteristics
     *     of the record to be received. Can be null to accept any record.
     * @return The `Record` object that matches the specified processing hint, or the next record if
     *     no hint is provided.
     */
    public Record receiveNextRelevantRecord(LayerProcessingHint desiredHint) throws IOException {

        final boolean isDtls =
                recordLayer.getContext().getChooser().getSelectedProtocolVersion().isDTLS();
        final boolean dtlsReorderRecords =
                isDtls && recordLayer.getContext().getConfig().getReorderReceivedDtlsRecords();

        // keep parsing until we find the record we have the hint for
        while (true) {

            LOGGER.trace("trying to receive next record");

            Record record = null;
            // get a complete record, either from the lower layer or
            // first drain order manager (if we account for dtls reordering)
            if (dtlsReorderRecords) {
                record =
                        getDtlsRecordOrderHandler()
                                .getNextOrderConformingRecord(
                                        lastObservedEpoch, lastSequenceNumber);
                if (record != null) {
                    LOGGER.trace(
                            "We already have a record in the queue that fits the order requirement: {}",
                            record);
                }
            }

            if (record == null) {
                // parse new record
                record = recordLayer.parseNextRecord();
                LOGGER.trace(
                        "Parsed fresh record: {}, seq num {}, message len length {}",
                        record,
                        record.getSequenceNumber().getValue(),
                        record.getCleanProtocolMessageBytes().getValue().length);
            }

            if (dtlsReorderRecords) {
                // pass record to order handler and skip iteration if it is not order conform
                getDtlsRecordOrderHandler().addRecord(record);

                LOGGER.trace(
                        "Checking record order. We need a record that fits last epoch {}, last seq num {}",
                        lastObservedEpoch,
                        lastSequenceNumber);
                record =
                        getDtlsRecordOrderHandler()
                                .getNextOrderConformingRecord(
                                        lastObservedEpoch, lastSequenceNumber);
                if (record != null) {
                    LOGGER.trace("We found a record that fits the order requirement: {}", record);
                }
            }

            if (record == null) {
                // no order conform record found. Parse more
                LOGGER.trace("No next record in order. Parsing more records.");
                continue;
            }

            if (isDtls) {
                // update last observed counters
                lastObservedEpoch = record.getEpoch().getValue();
                lastSequenceNumber = record.getSequenceNumber().getValue().intValue();
                LOGGER.trace(
                        "Updated lastObservedEpoch to {}, lastSequenceNumber to {}",
                        lastObservedEpoch,
                        lastSequenceNumber);
            }

            // extract message type of new record
            RecordLayerHint currentHint;
            if (isDtls) {
                currentHint =
                        new RecordLayerHint(
                                record.getContentMessageType(),
                                record.getEpoch().getValue(),
                                record.getSequenceNumber().getValue().intValue());
            } else {
                currentHint = new RecordLayerHint(record.getContentMessageType());
            }

            // only set the currentInputStream when we received the expected message
            if (desiredHint == null || currentHint.equals(desiredHint)) {
                getRecordLayer()
                        .extendCurrentStream(
                                currentHint, record.getCleanProtocolMessageBytes().getValue());
                // return, because we found the desired record
                return record;
            }

            // not the desired record, we keep parsing and extend the next stream
            getRecordLayer()
                    .extendNextStream(
                            currentHint, record.getCleanProtocolMessageBytes().getValue());
        }
    }

    /**
     * Checks whether we are in a setting that uses DTLS and record reordering and whether we are
     * able to fully empty a buffer of stored records to record sequence in order, without reading
     * from any streams or parsing any new records.
     */
    public boolean canDrainOrderedDtlsRecords() {
        final boolean isDtls =
                recordLayer.getContext().getChooser().getSelectedProtocolVersion().isDTLS();
        final boolean dtlsReorderRecords =
                isDtls && recordLayer.getContext().getConfig().getReorderReceivedDtlsRecords();

        if (!dtlsReorderRecords) {
            return false;
        }

        return getDtlsRecordOrderHandler().drainable(lastSequenceNumber, lastObservedEpoch);
    }

    public int getLastObservedEpoch() {
        return lastObservedEpoch;
    }

    public void setLastObservedEpoch(int lastObservedEpoch) {
        this.lastObservedEpoch = lastObservedEpoch;
    }

    public int getLastSequenceNumber() {
        return lastSequenceNumber;
    }

    public void setLastSequenceNumber(int lastSequenceNumber) {
        this.lastSequenceNumber = lastSequenceNumber;
    }

    public RecordLayer getRecordLayer() {
        return recordLayer;
    }

    public DtlsRecordOrderHandler getDtlsRecordOrderHandler() {
        return dtlsRecordOrderHandler;
    }
}
