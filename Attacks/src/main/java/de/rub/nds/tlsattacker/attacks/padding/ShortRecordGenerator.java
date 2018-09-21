/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.LinkedList;
import java.util.List;

public class ShortRecordGenerator extends PaddingRecordGenerator {

    @Override
    public List<Record> getRecords(CipherSuite suite, ProtocolVersion version) {
        int blockSize = AlgorithmResolver.getCipher(suite).getBlocksize();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        List<Record> recordList = new LinkedList<>();
        recordList.addAll(createRecordsWithModifiedMac());
        recordList.addAll(createRecordsWithModifiedPadding());
        recordList.addAll(createRecordsWithPlainData(blockSize, macSize));
        return recordList;
    }

    private List<Record> createRecordsWithPlainData(int blocksize, int macSize) {
        List<Record> records = new LinkedList<>();
        for (int i = 0; i < 64; i++) {
            byte[] padding = createPaddingBytes(i);
            int messageSize = blocksize - (padding.length % blocksize);
            byte[] message = new byte[messageSize];
            byte[] plain = ArrayConverter.concatenate(message, padding);
            if (plain.length > macSize) {
                Record r = createRecordWithPlainData(plain);
                records.add(r);
            }
        }
        byte[] plain = new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255 };
        if (plain.length > macSize) {
            Record r = createRecordWithPlainData(plain);
            records.add(r);
        }
        plain = new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255 };
        if (plain.length > macSize) {
            Record r = createRecordWithPlainData(plain);
            records.add(r);
        }
        return records;
    }

    private Record createRecordWithPlainData(byte[] plain) {
        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray plainData = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValue(plain);
        plainData.setModification(modifier);
        r.getComputations().setPlainRecordBytes(plainData);
        return r;
    }

    private List<Record> createRecordsWithModifiedPadding() {
        List<Record> records = new LinkedList<>();

        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray padding = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1 }, 0);
        padding.setModification(modifier);
        r.getComputations().setPadding(padding);
        records.add(r);

        return records;
    }

    private List<Record> createRecordsWithModifiedMac() {
        List<Record> records = new LinkedList<>();

        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray mac = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1, 1, 1 }, 0);
        mac.setModification(modifier);
        r.getComputations().setMac(mac);
        records.add(r);

        return records;
    }
}
