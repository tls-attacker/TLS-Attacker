/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.preparator;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

/**
 * The cleanrecordbytes should be set when the record preparator received the
 * record
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordPreparator extends AbstractRecordPreparator<Record> {

    private final Record record;
    private final Encryptor encryptor;

    public RecordPreparator(Chooser chooser, Record record, Encryptor encryptor, ProtocolMessageType type) {
        super(chooser, record, type);
        this.record = record;
        this.encryptor = encryptor;
    }

    @Override
    public void prepare() {
        record.setContentType(type.getValue());
        record.setProtocolVersion(chooser.getSelectedProtocolVersion().getValue());
        record.setSequenceNumber(BigInteger.valueOf(chooser.getSequenceNumber()));
        encryptor.encrypt(record);
        record.setLength(record.getProtocolMessageBytes().getValue().length);
    }
}