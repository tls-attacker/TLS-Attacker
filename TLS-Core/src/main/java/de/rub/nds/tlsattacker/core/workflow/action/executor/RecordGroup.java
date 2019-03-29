/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class RecordGroup {

    /**
     * Splits a list of received records into RecordGroups such that records in
     * each record group share the following characteristics: 1. they are of the
     * same type (blob or real records); 2. they use the same cipher state (for
     * DTLS, this means they have the same epochs); 3. their content is of the
     * same type.
     * 
     * 
     * This allows for records in a particular RecordGroup to be processed
     * together.
     */
    static final List<RecordGroup> parseRecordGroups(List<AbstractRecord> records, TlsContext context) {
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
