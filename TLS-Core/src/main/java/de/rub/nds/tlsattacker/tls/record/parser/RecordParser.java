/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.parser;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.RecordByteLength;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.record.Record;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class RecordParser extends Parser<Record> {

    private ProtocolVersion version;

    public RecordParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array);
        this.version = version;
    }

    @Override
    public Record parse() {
        Record record = new Record();
        parseContentType(record);
        parseVersion(record);
        parseLength(record);
        parseProtocolMessageBytes(record);
        return record;
    }

    private void parseContentType(Record record) {
        record.setContentType(parseByteField(RecordByteLength.CONTENT_TYPE));
    }

    private void parseVersion(Record record) {
        record.setProtocolVersion(parseByteArrayField(RecordByteLength.PROTOCOL_VERSION));
    }

    private void parseLength(Record record) {
        record.setLength(parseIntField(RecordByteLength.RECORD_LENGTH));
    }

    private void parseProtocolMessageBytes(Record record) {
        record.setProtocolMessageBytes(parseByteArrayField(record.getLength().getValue()));
    }
}
