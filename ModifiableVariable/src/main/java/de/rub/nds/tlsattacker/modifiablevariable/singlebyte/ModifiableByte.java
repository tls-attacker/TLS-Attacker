package de.rub.nds.tlsattacker.modifiablevariable.singlebyte;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlSeeAlso({ ByteAddModification.class, ByteExplicitValueModification.class, ByteSubtractModification.class,
	ByteXorModification.class })
@XmlType(propOrder = { "originalValue", "modification" })
public class ModifiableByte extends ModifiableVariable<Byte> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<Byte> vm = ByteModificationFactory.createRandomModification();
	setModification(vm);
    }

    public Byte getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(Byte originalValue) {
	this.originalValue = originalValue;
    }

    @Override
    public boolean isOriginalValueModified() {
	return originalValue != null && originalValue.compareTo(getValue()) != 0;
    }
}
