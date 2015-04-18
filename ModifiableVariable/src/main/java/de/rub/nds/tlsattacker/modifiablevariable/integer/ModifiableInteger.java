package de.rub.nds.tlsattacker.modifiablevariable.integer;

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
@XmlSeeAlso({ IntegerAddModification.class, IntegerExplicitValueModification.class, IntegerSubtractModification.class,
	IntegerXorModification.class })
@XmlType(propOrder = { "originalValue", "modification" })
public class ModifiableInteger extends ModifiableVariable<Integer> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<Integer> vm = IntegerModificationFactory.createRandomModification();
	setModification(vm);
    }

    public Integer getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(Integer originalValue) {
	this.originalValue = originalValue;
    }
}
