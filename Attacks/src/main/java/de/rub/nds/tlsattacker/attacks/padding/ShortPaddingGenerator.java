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
import de.rub.nds.modifiablevariable.bytearray.ByteArrayDeleteModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.padding.vector.ModifiedMacVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.ModifiedPaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.PlainPaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.TrippleVector;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

/**
 *
 *
 */
public class ShortPaddingGenerator extends PaddingVectorGenerator {

    /**
     *
     * @param suite
     * @param version
     * @return
     */
    @Override
    public List<PaddingVector> getVectors(CipherSuite suite, ProtocolVersion version) {
        int blockSize = AlgorithmResolver.getCipher(suite).getBlocksize();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        List<PaddingVector> vectorList = new LinkedList<>();
        vectorList.addAll(createBasicMacVectors(suite, version));
        vectorList.addAll(createMissingMacByteVectors(suite, version));
        vectorList.addAll(createOnlyPaddingVectors(suite, version));
        vectorList.addAll(createClassicModifiedPadding(suite, version));
        // vectorList.addAll(createVectorWithModifiedMac());
        // vectorList.addAll(createVectorWithModifiedPadding());
        // vectorList.addAll(createRecordsWithPlainData(blockSize, macSize));
        return vectorList;
    }

    /**
     * Create Vectors with Valid Padding but invalid Mac on 3 different
     * Positions
     *
     * @param suite
     * @param version
     * @return
     */
    private List<PaddingVector> createBasicMacVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        for (VariableModification modification : createFlippedModifications(macSize)) {
            vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[64 - macSize - 4]),
                    modification, null));
        }
        return vectorList;
    }

    /**
     * Creates vectors where the first mac byte is missing
     *
     * @param suite
     * @param version
     * @return
     */
    private List<PaddingVector> createMissingMacByteVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        byte[] padding = createPaddingBytes(64 - macSize + 1 - 1);
        vectorList.add(new TrippleVector("MissingMacByte-ValidPadding", new ByteArrayExplicitValueModification(new byte[0]),
                new ByteArrayDeleteModification(0, 1), new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(64 - macSize + 1 - 1);
        padding[0] ^= 0x80; // flip first padding byte last bit
        vectorList.add(new TrippleVector("MissingMacByte-Padding[" + 0 + "]LastBit", new ByteArrayExplicitValueModification(new byte[0]),
                new ByteArrayDeleteModification(0, 1), new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(64 - macSize + 1 - 1);
        padding[(64 - macSize + 1) / 2] ^= 0x8; // flip middle padding byte
        // middle bit
        vectorList.add(new TrippleVector("MissingMacByte-Padding[" + ((64 - macSize + 1) / 2) + "]MiddleBit", new ByteArrayExplicitValueModification(new byte[0]),
                new ByteArrayDeleteModification(0, 1), new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(64 - macSize + 1 - 1);
        padding[(64 - macSize + 1 - 1)] ^= 0x01; // flip last padding byte first
        // bit
        vectorList.add(new TrippleVector("MissingMacByte-Padding[" + ((64 - macSize + 1 - 1) / 2) + "]FirstBit", new ByteArrayExplicitValueModification(new byte[0]),
                new ByteArrayDeleteModification(0, 1), new ByteArrayExplicitValueModification(padding))
        );
        return vectorList;
    }

    private List<PaddingVector> createOnlyPaddingVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        byte[] plain = createPaddingBytes(63);
        vectorList.add(createVectorWithPlainData(plain));
        plain = new byte[]{(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255,};
        vectorList.add(createVectorWithPlainData(plain));
        return vectorList;
    }

    private List<PaddingVector> createClassicModifiedPadding(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        // valid mac
        byte[] padding = createPaddingBytes(64 - macSize - 1);
        padding[0] ^= 0x80; // flip first padding byte last bit
        vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[0]), null,
                new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(64 - macSize - 1);
        padding[(64 - macSize + 1) / 2] ^= 0x8; // flip middle padding byte
        // middle bit
        vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[0]), null,
                new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(64 - macSize - 1);
        padding[padding.length - 1] ^= 0x01; // flip last padding byte first
        // bit
        vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[0]), null,
                new ByteArrayExplicitValueModification(padding)));

        // invalid mac
        padding = createPaddingBytes(64 - macSize - 1);
        vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[0]),
                new ByteArrayXorModification(new byte[0x01], 0), new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(64 - macSize - 1);
        padding[0] ^= 0x80; // flip first padding byte last bit
        vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[0]),
                new ByteArrayXorModification(new byte[0x01], 0), new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(64 - macSize - 1);
        padding[(64 - macSize + 1) / 2] ^= 0x8; // flip middle padding byte
        // middle bit
        vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[0]),
                new ByteArrayXorModification(new byte[0x01], 0), new ByteArrayExplicitValueModification(padding)));
        padding = createPaddingBytes(64 - macSize - 1);
        padding[padding.length - 1] ^= 0x01; // flip last padding byte first
        // bit
        vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[0]),
                new ByteArrayXorModification(new byte[0x01], 0), new ByteArrayExplicitValueModification(padding)));

        if (macSize != 48) {
            padding = createPaddingBytes(6);
            vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[64 - macSize - 7]), null,
                    new ByteArrayExplicitValueModification(padding)));
            padding = createPaddingBytes(6);
            padding[0] ^= 0x80; // flip first padding byte last bit
            vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[64 - macSize - 7]), null,
                    new ByteArrayExplicitValueModification(padding)));
            padding = createPaddingBytes(6);
            padding[6 / 2] ^= 0x8; // flip middle padding byte
            // middle bit
            vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[64 - macSize - 7]), null,
                    new ByteArrayExplicitValueModification(padding)));
            padding = createPaddingBytes(6);
            padding[padding.length - 1] ^= 0x01; // flip last padding byte
            // first bit
            vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[64 - macSize - 7]), null,
                    new ByteArrayExplicitValueModification(padding)));

            // invalid mac
            padding = createPaddingBytes(6);
            vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[64 - macSize - 7]),
                    new ByteArrayXorModification(new byte[0x01], 0), new ByteArrayExplicitValueModification(padding)));
            padding = createPaddingBytes(6);
            padding[0] ^= 0x80; // flip first padding byte last bit
            vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[64 - macSize - 7]),
                    new ByteArrayXorModification(new byte[0x01], 0), new ByteArrayExplicitValueModification(padding)));
            padding = createPaddingBytes(6);
            padding[6 / 2] ^= 0x8; // flip middle padding byte
            // middle bit
            vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[64 - macSize - 7]),
                    new ByteArrayXorModification(new byte[0x01], 0), new ByteArrayExplicitValueModification(padding)));
            padding = createPaddingBytes(6);
            padding[padding.length - 1] ^= 0x01; // flip last padding byte
            // first bit
            vectorList.add(new TrippleVector(new ByteArrayExplicitValueModification(new byte[64 - macSize - 7]),
                    new ByteArrayXorModification(new byte[0x01], 0), new ByteArrayExplicitValueModification(padding)));
        }

        return vectorList;
    }

    private List<VariableModification> createFlippedModifications(int byteLength) {
        List<VariableModification> modificationList = new LinkedList<>();
        modificationList.add(new ByteArrayXorModification(new byte[]{0x01}, byteLength - 1)); // Last
        // Byte
        // /
        // first
        // bit
        modificationList.add(new ByteArrayXorModification(new byte[]{0x08}, byteLength / 2)); // Some
        // Byte
        // in
        // the
        // middle
        // /
        // some
        // bit
        // in
        // the
        // middle
        modificationList.add(new ByteArrayXorModification(new byte[]{(byte) 0x80}, 0)); // first
        // byte/
        // last
        // bit
        return modificationList;
    }

    private List<PaddingVector> createRecordsWithPlainData(int blocksize, int macSize) {
        List<PaddingVector> vectorList = new LinkedList<>();
        for (int i = 0; i < 64; i++) {
            byte[] padding = createPaddingBytes(i);
            int messageSize = blocksize - (padding.length % blocksize);
            byte[] message = new byte[messageSize];
            byte[] plain = ArrayConverter.concatenate(message, padding);
            if (plain.length > macSize) {
                PaddingVector vector = createVectorWithPlainData(plain);
                vectorList.add(vector);
            }
        }
        byte[] plain = new byte[]{(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255};
        if (plain.length > macSize) {
            PaddingVector vector = createVectorWithPlainData(plain);
            vectorList.add(vector);
        }
        plain = new byte[]{(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
            (byte) 255};
        if (plain.length > macSize) {
            PaddingVector vector = createVectorWithPlainData(plain);
            vectorList.add(vector);
        }
        return vectorList;
    }

    private PaddingVector createVectorWithPlainData(byte[] plain) {
        return new PlainPaddingVector(
                (ByteArrayExplicitValueModification) ByteArrayModificationFactory.explicitValue(plain));
    }

    private List<PaddingVector> createVectorWithModifiedPadding() {
        List<PaddingVector> records = new LinkedList<>();
        records.add(new ModifiedPaddingVector(ByteArrayModificationFactory.xor(new byte[]{1}, 0)));
        return records;
    }

    private List<PaddingVector> createVectorWithModifiedMac() {
        List<PaddingVector> vectors = new LinkedList<>();
        vectors.add(new ModifiedMacVector((ByteArrayXorModification) ByteArrayModificationFactory.xor(new byte[]{1,
            1, 1}, 0)));
        return vectors;
    }
}
