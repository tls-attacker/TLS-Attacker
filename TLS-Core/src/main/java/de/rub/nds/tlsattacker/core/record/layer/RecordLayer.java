/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.layer;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class RecordLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Tries to parse rawBytes into AbstractRecords. If this is not possible a
     * Parser Exception is thrown
     *
     * @param rawBytes
     *            Bytes to parse
     * @return List of parsed records
     */
    public abstract List<AbstractRecord> parseRecords(byte[] rawBytes) throws ParserException;

    /**
     * Tries to parse rawBytes into AbstractRecords. Exceptions which might
     * occur are handled.
     *
     * @param rawBytes
     *            Bytes to parse
     * @return List of parsed records
     */
    public abstract List<AbstractRecord> parseRecordsSoftly(byte[] rawBytes);

    public abstract void decryptRecord(AbstractRecord records);

    public abstract byte[] prepareRecords(byte[] data, ProtocolMessageType contentType, List<AbstractRecord> records);

    public abstract void setRecordCipher(RecordCipher cipher);

    public abstract void updateEncryptionCipher();

    public abstract void updateDecryptionCipher();

    public abstract RecordCipher getEncryptor();

    public abstract RecordCipher getDecryptor();

    public abstract AbstractRecord getFreshRecord();

    public abstract void updateCompressor();

    public abstract void updateDecompressor();
}
