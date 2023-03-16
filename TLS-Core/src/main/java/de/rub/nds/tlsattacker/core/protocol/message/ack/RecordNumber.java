/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.ack;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RecordNumber that = (RecordNumber) o;
        return Objects.equals(epoch, that.epoch)
                && Objects.equals(sequenceNumber, that.sequenceNumber);
    }

    @Override
    public int hashCode() {
        return Objects.hash(epoch, sequenceNumber);
    }
}
