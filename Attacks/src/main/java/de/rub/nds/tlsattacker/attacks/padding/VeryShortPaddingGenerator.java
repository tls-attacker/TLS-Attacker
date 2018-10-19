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
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.tlsattacker.attacks.padding.vector.ModifiedMacVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.ModifiedPaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.padding.vector.PlainPaddingVector;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.LinkedList;
import java.util.List;

/**
 *
 *
 */
public class VeryShortPaddingGenerator extends PaddingVectorGenerator {

    /**
     *
     * @param suite
     * @param version
     * @return
     */
    @Override
    public List<PaddingVector> getVectors(CipherSuite suite, ProtocolVersion version) {
        List<PaddingVector> vectorList = new LinkedList<>();
        vectorList.addAll(createVectorWithModifiedMac());
        vectorList.addAll(createVectorWithModifiedPadding());
        vectorList.addAll(createVectorWithPlainData());
        return vectorList;
    }

    private List<PaddingVector> createVectorWithPlainData() {
        List<PaddingVector> vectorList = new LinkedList<>();
        byte[] plain = createPaddingBytes(63);
        vectorList.add(createVectorWithPlainData(plain));
        plain = new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, };
        vectorList.add(createVectorWithPlainData(plain));
        return vectorList;
    }

    private PaddingVector createVectorWithPlainData(byte[] plain) {
        return new PlainPaddingVector(
                (ByteArrayExplicitValueModification) ByteArrayModificationFactory.explicitValue(plain));
    }

    private List<PaddingVector> createVectorWithModifiedPadding() {
        List<PaddingVector> records = new LinkedList<>();
        records.add(new ModifiedPaddingVector(ByteArrayModificationFactory.xor(new byte[] { 1 }, 0)));
        return records;
    }

    private List<PaddingVector> createVectorWithModifiedMac() {
        List<PaddingVector> vectors = new LinkedList<>();
        vectors.add(new ModifiedMacVector((ByteArrayXorModification) ByteArrayModificationFactory.xor(new byte[] { 1,
                1, 1 }, 0)));
        return vectors;
    }
}
