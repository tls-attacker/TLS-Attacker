/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class RecordCryptoUnit {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ArrayList<RecordCipher> recordCipherList;

    public RecordCryptoUnit(RecordCipher recordCipher) {
        this.recordCipherList = new ArrayList<>();
        recordCipherList.add(0, recordCipher);
    }

    public RecordCipher getRecordMostRecentCipher() {
        return recordCipherList.get(recordCipherList.size() - 1);
    }

    /**
     * Tries to guess the correct epoch based on the given low-order two bits of the epoch (DTLS
     * 1.3). For that, it walks backwards through the list of ciphers, comparing each index modulo 4
     * against the provided epoch bits. On the first match, it sets the record’s full epoch and
     * returns that cipher.
     */
    public RecordCipher getRecordCipherForEpochBits(int epochBits, Record record) {
        for (int i = recordCipherList.size() - 1; i >= 0; i--) {
            if (i % 4 == epochBits) {
                record.setEpoch(i);
                return recordCipherList.get(i);
            }
        }
        LOGGER.warn("Got no RecordCipher for epoch bits: {}", epochBits);
        return null;
    }

    /** Return true, if we are still in epoch 0 (DTLS). */
    public boolean isEpochZero() {
        return recordCipherList.size() == 1;
    }

    public RecordCipher getRecordCipher(int epoch) {
        if (recordCipherList.size() > epoch && recordCipherList.get(epoch) != null) {
            return recordCipherList.get(epoch);
        } else {
            LOGGER.warn("Got no RecordCipher for epoch: {}. Using epoch 0 cipher", epoch);
            return recordCipherList.get(0);
        }
    }

    public void addNewRecordCipher(RecordCipher recordCipher) {
        this.recordCipherList.add(recordCipher);
    }

    public void removeAllCiphers() {
        this.recordCipherList = new ArrayList<>();
    }

    public void removeCiphers(int toRemove) {
        while (toRemove > 0 && !recordCipherList.isEmpty()) {
            recordCipherList.remove(recordCipherList.size() - 1);
            toRemove--;
        }
        if (toRemove > 0) {
            LOGGER.warn("Could not remove as many ciphers as specified");
        }
    }
}
