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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.Objects;

/**
 *
 */
public class CleanAndPaddingVector extends PaddingVector {

    private final VariableModification paddingModification;
    private final VariableModification cleanModification;

    public CleanAndPaddingVector(String name, String identifier, VariableModification paddingModification,
            VariableModification cleanModification) {
        super(name, identifier);
        this.paddingModification = paddingModification;
        this.cleanModification = cleanModification;
    }

    public VariableModification getPaddingModification() {
        return paddingModification;
    }

    public VariableModification getCleanModification() {
        return cleanModification;
    }

    @Override
    public Record createRecord() {
        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray byteArray = new ModifiableByteArray();
        byteArray.setModification(paddingModification);
        r.getComputations().setPadding(byteArray);
        byteArray = new ModifiableByteArray();
        byteArray.setModification(cleanModification);
        r.setCleanProtocolMessageBytes(byteArray);
        return r;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 11 * hash + Objects.hashCode(this.paddingModification);
        hash = 11 * hash + Objects.hashCode(this.cleanModification);
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
        final CleanAndPaddingVector other = (CleanAndPaddingVector) obj;
        if (!Objects.equals(this.paddingModification, other.paddingModification)) {
            return false;
        }
        if (!Objects.equals(this.cleanModification, other.cleanModification)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "" + name + "{" + "paddingModification=" + paddingModification + ", cleanModification="
                + cleanModification + '}';
    }

    @Override
    public int getRecordLength(CipherSuite testedSuite, ProtocolVersion testedVersion, int appDataLength) {
        Record r = createRecord();
        r.setCleanProtocolMessageBytes(new byte[appDataLength]);
        int completeLength = r.getCleanProtocolMessageBytes().getValue().length;
        completeLength += AlgorithmResolver.getMacAlgorithm(testedVersion, testedSuite).getSize();
        int paddingLength = AlgorithmResolver.getCipher(testedSuite).getBlocksize()
                - (completeLength % AlgorithmResolver.getCipher(testedSuite).getBlocksize());
        completeLength += paddingLength;

        return completeLength;
    }
}
