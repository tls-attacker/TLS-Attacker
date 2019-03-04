/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.parser.AbstractRecordParser;
import de.rub.nds.tlsattacker.core.record.parser.BlobRecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.AbstractRecordPreparator;
import de.rub.nds.tlsattacker.core.record.preparator.BlobRecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.AbstractRecordSerializer;
import de.rub.nds.tlsattacker.core.record.serializer.BlobRecordSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 * A Blob Record is not a record in a conventional sense but is rather a non
 * exisiting record and represents just a collection of bytes. Is used for
 * unparseable Records and for SSLv2
 */
public class BlobRecord extends AbstractRecord {

    private RecordCryptoComputations computations;

    public BlobRecord() {
    }

    public BlobRecord(Config config) {
        super(config);
    }

    @Override
    public AbstractRecordPreparator getRecordPreparator(Chooser chooser, Encryptor encryptor,
            RecordCompressor compressor, ProtocolMessageType type) {
        return new BlobRecordPreparator(chooser, this, encryptor, type, compressor);
    }

    @Override
    public AbstractRecordParser getRecordParser(int startposition, byte[] array, ProtocolVersion version) {
        return new BlobRecordParser(startposition, array, version);
    }

    @Override
    public AbstractRecordSerializer getRecordSerializer() {
        return new BlobRecordSerializer(this);
    }

    @Override
    public void adjustContext(TlsContext context) {
        // do nothing
    }

    public RecordCryptoComputations getComputations() {
        return computations;
    }

    public void setComputations(RecordCryptoComputations computations) {
        this.computations = computations;
    }

    @Override
    public void prepareComputations() {
        computations = new RecordCryptoComputations();
    }

    @Override
    public String toString() {
        return "BlobRecord{" + "computations=" + computations + '}';
    }
}
