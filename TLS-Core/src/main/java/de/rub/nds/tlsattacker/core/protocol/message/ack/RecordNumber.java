/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.ack;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.core.record.Record;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.math.BigInteger;
import java.util.Objects;

@XmlAccessorType(XmlAccessType.FIELD)
public class RecordNumber extends ModifiableVariableHolder {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableBigInteger epoch;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableBigInteger sequenceNumber;

    public RecordNumber() {}

    public RecordNumber(BigInteger epoch, BigInteger sequenceNumber) {
        this.epoch = ModifiableVariableFactory.safelySetValue(this.epoch, epoch);
        this.sequenceNumber =
                ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    public RecordNumber(Record record) {
        this.epoch =
                ModifiableVariableFactory.safelySetValue(
                        this.epoch, BigInteger.valueOf(record.getEpoch().getValue()));
        this.sequenceNumber =
                ModifiableVariableFactory.safelySetValue(
                        this.sequenceNumber, record.getSequenceNumber().getValue());
    }

    public ModifiableBigInteger getEpoch() {
        return epoch;
    }

    public void setEpoch(ModifiableBigInteger epoch) {
        this.epoch = epoch;
    }

    public void setEpoch(BigInteger epoch) {
        this.epoch = ModifiableVariableFactory.safelySetValue(this.epoch, epoch);
    }

    public ModifiableBigInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableBigInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(BigInteger sequenceNumber) {
        this.sequenceNumber =
                ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + Objects.hashCode(this.epoch);
        hash = 97 * hash + Objects.hashCode(this.sequenceNumber);
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
        final RecordNumber other = (RecordNumber) obj;
        if (!Objects.equals(this.epoch, other.epoch)) {
            return false;
        }
        return Objects.equals(this.sequenceNumber, other.sequenceNumber);
    }
}
