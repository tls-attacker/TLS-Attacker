/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A RecordGroup comprises records which should be decrypted/processed together.
 * They share the following characteristics: 1. they are of the same type (blob
 * or real records); 2. they use the same cipher state (for DTLS, this means
 * they have the same epoch); 3. their content is of the same type.
 * 
 * The class also provides functionality for grouping records into RecordGroups,
 * decrypting and parsing them.
 */
public class RecordGroup {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Arranges a list of records into RecordGroups.
     */
    // one could implement this into a RecordSplitter class
    static final List<RecordGroup> generateRecordGroups(List<AbstractRecord> records, TlsContext context) {
        List<RecordGroup> recordGroups = new LinkedList<>();
        if (records.isEmpty()) {
            return recordGroups;
        }

        RecordGroup group = new RecordGroup(context);
        recordGroups.add(group);
        for (AbstractRecord record : records) {
            if (!group.addRecord(record)) {
                group = new RecordGroup(context);
                recordGroups.add(group);
                group.addRecord(record);
            }
        }

        return recordGroups;
    }

    private List<AbstractRecord> records = new LinkedList<>();
    private boolean isDtls;

    private RecordGroup(TlsContext context) {
        isDtls = context.getChooser().getSelectedProtocolVersion().isDTLS();
    }

    public ProtocolMessageType getProtocolMessageType() {
        if (!records.isEmpty()) {
            return ProtocolMessageType.getContentType(records.get(0).getContentMessageType().getValue());
        }
        return null;
    }

    public Integer getDtlsEpoch() {
        if (!records.isEmpty()) {
            return getRecordEpoch(records.get(0));
        }
        return null;
    }

    private Integer getRecordEpoch(AbstractRecord record) {
        if (isDtls && record instanceof Record) {
            return ((Record) record).getEpoch().getValue();
        }
        return null;
    }

    public List<AbstractRecord> getRecords() {
        return Collections.unmodifiableList(records);
    }

    public byte[] getCleanBytes() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (AbstractRecord record : getRecords()) {
            try {
                stream.write(record.getCleanProtocolMessageBytes().getValue());
            } catch (IOException ex) {
                LOGGER.warn("Could not write CleanProtocolMessage bytes to Array");
                LOGGER.debug(ex);
            }
        }
        return stream.toByteArray();
    }

    public void decryptRecords(TlsContext context) {
        for (AbstractRecord record : getRecords()) {
            context.getRecordLayer().decryptRecord(record);
        }
    }

    public void adjustContext(TlsContext context) {
        for (AbstractRecord record : getRecords()) {
            record.adjustContext(context);
        }
    }

    public boolean isMacOrPadInvalid(TlsContext context) {
        for (AbstractRecord record : getRecords()) {
            if (record instanceof Record) {
                if (Boolean.FALSE.equals(((Record) record).getComputations().getMacValid())
                        || Boolean.FALSE.equals(((Record) record).getComputations().getPaddingValid()))
                    return true;
            }
        }
        return false;
    }

    private boolean addRecord(AbstractRecord record) {
        boolean isFitting = false;
        if (records.isEmpty()) {
            isFitting = true;
        } else {
            if (Objects.equals(record.getContentMessageType(), getProtocolMessageType())
                    && record.getClass().equals(records.get(0).getClass())) {
                if (isDtls) {
                    if (Objects.equals(getRecordEpoch(record), getDtlsEpoch())) {
                        isFitting = true;
                    }
                } else {
                    isFitting = true;
                }
            }
        }

        if (isFitting) {
            records.add(record);
        }
        return isFitting;
    }
}
