/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.cert;

import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.record.Record;
import java.io.InputStream;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * //TODO I am not sure if this implementation is so smart since it extends Parser which is designed
 * for Message objects and is called ByteSeperator //I Think another logical abstraction is needed
 * here
 */
public class CleanRecordByteSeperator extends Parser<List<Record>> {

    private static Logger LOGGER = LogManager.getLogger();

    private final int defaultMaxSize;
    private final boolean createRecordsDynamically;

    public CleanRecordByteSeperator(
            int defaultMaxSize, InputStream stream, boolean createRecordsDynamically) {
        super(stream);
        this.defaultMaxSize = defaultMaxSize;
        this.createRecordsDynamically = createRecordsDynamically;
    }

    @Override
    public void parse(List<Record> records) {
        for (Record record : records) {
            Integer maxData = record.getMaxRecordLengthConfig();
            if (maxData == null) {
                maxData = defaultMaxSize;
            }
            record.setCleanProtocolMessageBytes(parseArrayOrTillEnd(maxData));
        }
        if (createRecordsDynamically) {
            while (getBytesLeft() > 0) {
                // There are still bytes left, we need to create additional records
                Record record = new Record(defaultMaxSize);
                record.setCleanProtocolMessageBytes(parseArrayOrTillEnd(defaultMaxSize));
                records.add(record);
            }
        }
    }
}
