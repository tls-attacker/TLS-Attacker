/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.bytearray;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.util.ByteArrayAdapter;
import java.io.Serializable;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlSeeAlso({ ByteArrayDeleteModification.class, ByteArrayExplicitValueModification.class,
	ByteArrayInsertModification.class, ByteArrayXorModification.class })
@XmlType(propOrder = { "originalValue", "modification" })
public class ModifiableByteArray extends ModifiableVariable<byte[]> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<byte[]> vm = ByteArrayModificationFactory.createRandomModification((byte[]) originalValue);
	setModification(vm);
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public byte[] getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(byte[] value) {
	this.originalValue = value;
    }

    @Override
    public boolean isOriginalValueModified() {
	return originalValue != null && !Arrays.equals(originalValue, getValue());
    }
}
