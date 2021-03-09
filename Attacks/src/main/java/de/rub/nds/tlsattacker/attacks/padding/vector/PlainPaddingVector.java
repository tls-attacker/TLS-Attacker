/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.padding.vector;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.attacks.general.Vector;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import java.util.Arrays;
import java.util.Objects;

/**
 *
 */
public class PlainPaddingVector extends PaddingVector {

    private final ByteArrayExplicitValueModification modification;

    public PlainPaddingVector(String name, String identifier, ByteArrayExplicitValueModification modification) {
        super(name, identifier);
        this.modification = modification;
    }

    public ByteArrayExplicitValueModification getModification() {
        return modification;
    }

    @Override
    public Record createRecord() {
        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray byteArray = new ModifiableByteArray();
        byteArray.setModification(modification);
        r.getComputations().setPlainRecordBytes(byteArray);
        return r;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 13 * hash + Objects.hashCode(this.modification);
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
        final PlainPaddingVector other = (PlainPaddingVector) obj;
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
        Record r = createRecord();
        r.getComputations().setPlainRecordBytes(new byte[appDataLength]);
        int size = r.getComputations().getPlainRecordBytes().getValue().length;

        return size;
    }
}
