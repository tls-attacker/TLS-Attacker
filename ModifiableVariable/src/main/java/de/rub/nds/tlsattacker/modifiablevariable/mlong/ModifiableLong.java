/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.mlong;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlSeeAlso({ LongAddModification.class, LongExplicitValueModification.class, LongSubtractModification.class,
	LongXorModification.class })
@XmlType(propOrder = { "originalValue", "modification" })
public class ModifiableLong extends ModifiableVariable<Long> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<Long> vm = LongModificationFactory.createRandomModification();
	setModification(vm);
    }

    public Long getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(Long originalValue) {
	this.originalValue = originalValue;
    }

    @Override
    public boolean isOriginalValueModified() {
	return originalValue != null && originalValue.compareTo(getValue()) != 0;
    }

    public byte[] getByteArray(int size) {
	return ArrayConverter.longToBytes(getValue(), size);
    }
}
