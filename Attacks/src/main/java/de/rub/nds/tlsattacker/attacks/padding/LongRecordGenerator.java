/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.LinkedList;
import java.util.List;

/**
 *
 *
 */
public class LongRecordGenerator extends PaddingRecordGenerator {

    /**
     *
     * @param suite
     * @param version
     * @return
     */
    @Override
    public List<Record> getRecords(CipherSuite suite, ProtocolVersion version) {
        List<Record> recordList = new LinkedList<>();
        recordList.addAll(getMacFlippedRecords(suite, version));
        recordList.addAll(getPaddingFlippedRecords(suite, version));
        recordList.addAll(getPlainRecords(suite, version));
        return recordList;
    }

    /**
     * Returns a byte array where each byte has a distinct bit set
     *
     * @return
     */
    private byte[] getBitflipArray() {
        byte[] map = new byte[8];
        for (int i = 0; i < 8; i++) {
            map[i] = (byte) (1 << i);
        }
        return map;
    }

    /**
     * Returns an array of arrays of modified paddings of length X
     *
     * @param length
     * @return
     */
    private byte[][] getModifiedPaddings(int length) {
        byte[][] map = new byte[length * 8][length];
        byte[] bitflipArray = getBitflipArray();
        byte[] correctPadding = createPaddingBytes(length);
        for (int j = 0; j < length * 8; j++) {
            System.arraycopy(correctPadding, 0, map[j], 0, length);
        }
        for (int i = 0; i < map.length; i++) {
            map[i][i / 8] ^= bitflipArray[i % 8];
        }
        return map;
    }

    private List<Record> getPaddingFlippedRecords(CipherSuite suite, ProtocolVersion version) {
        List<Record> recordList = new LinkedList<>();
        int blockSize = AlgorithmResolver.getCipher(suite).getBlocksize();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        for (int paddingLength = 0; paddingLength < 256; paddingLength++) {
            int messageSize = blockSize - ((paddingLength + macSize) % blockSize);
            byte[] message = new byte[messageSize];
            byte[][] paddings = getModifiedPaddings(paddingLength);
            for (byte[] padding : paddings) {
                Record r = new Record();
                r.prepareComputations();
                ModifiableByteArray modPadding = new ModifiableByteArray();
                modPadding.setModification(new ByteArrayExplicitValueModification(padding));
                r.getComputations().setPadding(modPadding);
                ModifiableByteArray modMessage = new ModifiableByteArray();
                modMessage.setModification(new ByteArrayExplicitValueModification(message));
                r.setCleanProtocolMessageBytes(message);
                recordList.add(r);
            }
        }
        return recordList;
    }

    private List<Record> getMacFlippedRecords(CipherSuite suite, ProtocolVersion version) {
        List<Record> recordList = new LinkedList<>();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        List<ByteArrayXorModification> allBitFlipModifications = getAllBitFlipModifications(macSize);
        for (ByteArrayXorModification modification : allBitFlipModifications) {
            Record r = new Record();
            r.prepareComputations();
            ModifiableByteArray modMac = new ModifiableByteArray();
            modMac.setModification(modification);
            r.getComputations().setMac(modMac);
            recordList.add(r);
        }
        return recordList;
    }

    private List<Record> getPlainRecords(CipherSuite suite, ProtocolVersion version) {
        List<Record> recordList = new LinkedList<>();
        int blockSize = AlgorithmResolver.getCipher(suite).getBlocksize();
        for (int paddingLength = 0; paddingLength < 256; paddingLength++) {
            int messageSize = blockSize - (paddingLength % blockSize);
            byte[] message = new byte[messageSize];
            byte[][] paddings = getModifiedPaddings(paddingLength);
            for (byte[] padding : paddings) {
                Record r = new Record();
                r.prepareComputations();
                byte[] plain = ArrayConverter.concatenate(message, padding);
                ModifiableByteArray modPlain = new ModifiableByteArray();
                modPlain.setModification(new ByteArrayExplicitValueModification(plain));
                r.getComputations().setPlainRecordBytes(modPlain);
                recordList.add(r);
            }
        }
        return recordList;
    }

    /**
     * Returns a List of modifications which flip each bit up to byte length X
     * indiviually
     *
     * @param targetLength
     * @return
     */
    private List<ByteArrayXorModification> getAllBitFlipModifications(int targetLength) {
        byte[] bitflipArray = getBitflipArray();
        List<ByteArrayXorModification> modificationList = new LinkedList<>();
        for (int i = 0; i < targetLength; i++) {
            for (int j = 0; j < 8; j++) {
                modificationList.add(new ByteArrayXorModification(new byte[] { bitflipArray[j] }, i));
            }
        }
        return modificationList;
    }
}
