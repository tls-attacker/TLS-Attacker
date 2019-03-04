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
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobRecordPreparator extends AbstractRecordPreparator {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BlobRecord record;
    private final Encryptor encryptor;
    private final RecordCompressor compressor;

    public BlobRecordPreparator(Chooser chooser, BlobRecord record, Encryptor encryptor, ProtocolMessageType type,
            RecordCompressor compressor) {
        super(chooser, record, type);
        this.record = record;
        this.encryptor = encryptor;
        this.compressor = compressor;
    }

    @Override
    public void prepare() {
        if (!chooser.getSelectedProtocolVersion().isTLS13()) {
            compressor.compress(record);
        }
        encryptor.encrypt(record);
        prepareContentMessageType(record);
    }

    private void prepareContentMessageType(BlobRecord record) {
        record.setContentMessageType(type);
        LOGGER.debug("ContentMessageType: " + record.getContentMessageType().getValue());
    }

}
