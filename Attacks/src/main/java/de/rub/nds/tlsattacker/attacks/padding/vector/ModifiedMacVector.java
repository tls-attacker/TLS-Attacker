/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding.vector;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.Objects;

/**
 *
 */
public class ModifiedMacVector extends PaddingVector {

    private final ByteArrayXorModification modification;

    public ModifiedMacVector(String name, String identifier, ByteArrayXorModification modification) {
        super(name, identifier);
        this.modification = modification;
    }

    public VariableModification getModification() {
        return modification;
    }

    @Override
    public Record createRecord() {
        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray byteArray = new ModifiableByteArray();
        byteArray.setModification(modification);
        r.getComputations().setMac(byteArray);
        return r;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 47 * hash + Objects.hashCode(this.modification);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ModifiedMacVector other = (ModifiedMacVector) obj;
        if (!Objects.equals(this.modification, other.modification)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "" + name + "{" + "modification=" + modification + '}';
    }

    @Override
    public int getRecordLength(CipherSuite testedSuite, ProtocolVersion testedVersion, int appDataLength) {
        int completeLength = appDataLength;

        completeLength += AlgorithmResolver.getMacAlgorithm(testedVersion, testedSuite).getSize();
        int paddingLength = AlgorithmResolver.getCipher(testedSuite).getBlocksize()
                - (completeLength % AlgorithmResolver.getCipher(testedSuite).getBlocksize());
        completeLength += paddingLength;
        return completeLength;
    }
}
