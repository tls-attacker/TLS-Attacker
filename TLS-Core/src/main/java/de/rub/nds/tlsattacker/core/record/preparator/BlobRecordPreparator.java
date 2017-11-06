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
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 *

 */
public class BlobRecordPreparator extends AbstractRecordPreparator {

    private final BlobRecord record;
    private final Encryptor encryptor;

    public BlobRecordPreparator(Chooser chooser, BlobRecord record, Encryptor encryptor, ProtocolMessageType type) {
        super(chooser, record, type);
        this.record = record;
        this.encryptor = encryptor;
    }

    @Override
    public void prepare() {
        encryptor.encrypt(record);
        prepareContentMessageType(record);
    }

    private void prepareContentMessageType(BlobRecord record) {
        record.setContentMessageType(type);
        LOGGER.debug("ContentMessageType: " + record.getContentMessageType().getValue());
    }

}
