package de.rub.nds.tlsattacker.modifiablevariable.biginteger;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import java.io.Serializable;
import java.math.BigInteger;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlSeeAlso({ BigIntegerAddModification.class, BigIntegerExplicitValueModification.class,
	BigIntegerSubtractModification.class, BigIntegerXorModification.class })
@XmlType(propOrder = { "originalValue", "modification" })
public class ModifiableBigInteger extends ModifiableVariable<BigInteger> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<BigInteger> vm = BigIntegerModificationFactory.createRandomModification();
	setModification(vm);
    }

    public BigInteger getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(BigInteger value) {
	this.originalValue = value;
    }

    @Override
    public boolean isOriginalValueModified() {
	return originalValue != null && (originalValue.compareTo(getValue()) != 0);
    }
}
