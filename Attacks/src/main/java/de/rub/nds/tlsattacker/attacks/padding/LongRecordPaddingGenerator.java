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
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.TrippleVector;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

public class LongRecordPaddingGenerator extends PaddingVectorGenerator {

    /**
     *
     * @param suite
     * @param version
     * @return
     */
    @Override
    public List<PaddingVector> getVectors(CipherSuite suite, ProtocolVersion version) {
        // Total plaintext size is not allowed to be bigger than 16384
        // MAC + Plaintext
        List<PaddingVector> vectorList = new LinkedList<>();
        int blockSize = AlgorithmResolver.getCipher(suite).getBlocksize();
        int macSize = AlgorithmResolver.getMacAlgorithm(version, suite).getSize();
        vectorList.add(new TrippleVector("ValidPlainData", "ValidPlainData", new ByteArrayExplicitValueModification(
                new byte[16384]), new ByteArrayExplicitValueModification(new byte[AlgorithmResolver.getMacAlgorithm(
                version, suite).getSize()]), new ByteArrayExplicitValueModification(
                createPaddingBytes(calculateValidPaddingSize(blockSize, macSize)))));
        vectorList.add(new TrippleVector("InvalidPlainData", "InvalidPlainData",
                new ByteArrayExplicitValueModification(new byte[16385]), new ByteArrayExplicitValueModification(
                        new byte[AlgorithmResolver.getMacAlgorithm(version, suite).getSize()]),
                new ByteArrayExplicitValueModification(createPaddingBytes(calculateInvalidPaddingSize(blockSize,
                        macSize)))));
        return vectorList;
    }

    private int calculateValidPaddingSize(int blocksize, int macSize) {
        return blocksize - (macSize % blocksize);
    }

    private int calculateInvalidPaddingSize(int blocksize, int macSize) {
        return (blocksize - (macSize % blocksize)) - 1;
    }

}
