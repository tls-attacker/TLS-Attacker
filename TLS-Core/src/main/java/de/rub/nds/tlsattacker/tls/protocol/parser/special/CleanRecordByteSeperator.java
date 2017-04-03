/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.special;

import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.record.Record;
import java.util.List;

/**
 * //TODO I am not sure if this implementation is so smart since it extends
 * Parser which is designed for Message objects and is called ByteSeperator //I
 * Think another logical abstraction is needed here
 * 
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CleanRecordByteSeperator extends Parser<List<Record>> {

    private final List<Record> records;
    private final int defaultMaxSize;

    public CleanRecordByteSeperator(List<Record> records, int defaultMaxSize, int startposition, byte[] array) {
        super(startposition, array);
        this.records = records;
        this.defaultMaxSize = defaultMaxSize;
    }

    @Override
    public List<Record> parse() {
        for (Record record : records) {
            Integer maxData = record.getMaxRecordLengthConfig();
            if (maxData == null) {
                maxData = defaultMaxSize;
            }
            record.setCleanProtocolMessageBytes(parseArrayOrTillEnd(maxData));
        }
        return records;
    }

}
