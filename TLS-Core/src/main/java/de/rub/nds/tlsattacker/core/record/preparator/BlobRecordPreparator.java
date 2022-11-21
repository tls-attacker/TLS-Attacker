/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.preparator;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobRecordPreparator extends AbstractRecordPreparator<BlobRecord> {

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
        LOGGER.debug("Preparing Record");
        if (!chooser.getSelectedProtocolVersion().isTLS13()) {
            compressor.compress(record);
        }
        encrypt();
        prepareContentMessageType(record);
    }

    public void encrypt() {
        LOGGER.debug("Encrypting Record");
        encryptor.encrypt(record);
    }

    private void prepareContentMessageType(BlobRecord record) {
        record.setContentMessageType(type);
        LOGGER.debug("ContentMessageType: " + record.getContentMessageType().getValue());
    }

}
