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
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.padding.vector.CleanAndPaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.ModifiedMacVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.PlainPaddingVector;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

/**
 *
 *
 */
public class MediumVectorGenerator extends PaddingVectorGenerator {

    /**
     *
     * @param suite
     * @param version
     * @return
     */
    @Override
    public List<PaddingVector> getVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        vectorList.addAll(getMacFlippedPaddingVectors(suite, version));
        vectorList.addAll(getPaddingFlippedPaddingVectors(suite, version));
        vectorList.addAll(getPlainPaddingVectors(suite, version));
        return vectorList;
    }

    /**
     * Returns an array of arrays of modified paddings of length X
     *
     * @param length
     * @return
     */
    private byte[][] getModifiedPaddings(int length) {
        byte[][] map = new byte[length][length];
        byte[] correctPadding = createPaddingBytes(length);
        for (int j = 0; j < length; j++) {
            System.arraycopy(correctPadding, 0, map[j], 0, length);
        }
        for (int i = 0; i < map.length; i++) {
            map[i][i] ^= 1;
        }
        return map;
    }

    private List<PaddingVector> getPaddingFlippedPaddingVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorLsit = new LinkedList<>();
        int blockSize = AlgorithmResolver.getCipher(suite).getBlocksize();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        for (int paddingLength = 0; paddingLength < 256; paddingLength++) {
            int messageSize = blockSize - ((paddingLength + macSize) % blockSize);
            byte[] message = new byte[messageSize];
            byte[][] paddings = getModifiedPaddings(paddingLength);
            for (byte[] padding : paddings) {
                VariableModification paddingModification = new ByteArrayExplicitValueModification(padding);
                VariableModification cleanModification = new ByteArrayExplicitValueModification(message);
                vectorLsit.add(new CleanAndPaddingVector("FlippedPadding " + ArrayConverter.bytesToHexString(padding)
                        + "-" + paddingLength, paddingModification, cleanModification));
            }
        }
        return vectorLsit;
    }

    private List<PaddingVector> getMacFlippedPaddingVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> paddingVectorList = new LinkedList<>();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        List<ByteArrayXorModification> allBitFlipModifications = getAllBitFlipModifications(macSize);
        for (ByteArrayXorModification modification : allBitFlipModifications) {
            paddingVectorList.add(new ModifiedMacVector("MacFlipped " + modification.getStartPosition() + "-"
                    + ArrayConverter.bytesToHexString(modification.getXor()), modification));
        }
        return paddingVectorList;
    }

    private List<PaddingVector> getPlainPaddingVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        int blockSize = AlgorithmResolver.getCipher(suite).getBlocksize();
        for (int paddingLength = 0; paddingLength < 256; paddingLength++) {
            int messageSize = blockSize - (paddingLength % blockSize);
            byte[] message = new byte[messageSize];
            byte[][] paddings = getModifiedPaddings(paddingLength);
            for (byte[] padding : paddings) {
                byte[] plain = ArrayConverter.concatenate(message, padding);
                vectorList.add(new PlainPaddingVector("Plain " + paddingLength + "-"
                        + ArrayConverter.bytesToHexString(plain), new ByteArrayExplicitValueModification(plain)));
            }
        }
        return vectorList;
    }

    /**
     * Returns a List of modifications which flip each bit up to byte length X
     * indiviually
     *
     * @param targetLength
     * @return
     */
    private List<ByteArrayXorModification> getAllBitFlipModifications(int targetLength) {
        List<ByteArrayXorModification> modificationList = new LinkedList<>();
        for (int i = 0; i < targetLength; i++) {
            modificationList.add(new ByteArrayXorModification(new byte[] { 1 }, i));
        }
        return modificationList;
    }
}
