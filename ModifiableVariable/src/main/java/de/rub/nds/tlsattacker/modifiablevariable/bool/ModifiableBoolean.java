/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.bool;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import java.math.BigInteger;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
@XmlRootElement
@XmlSeeAlso({ BooleanExplicitValueModification.class, BooleanExplicitValueModification.class })
@XmlType(propOrder = { "originalValue", "modification", })
public class ModifiableBoolean extends ModifiableVariable<Boolean> {

    private Boolean originalValue;

    public ModifiableBoolean() {
    }

    public ModifiableBoolean(Boolean originalValue) {
        this.originalValue = originalValue;
    }

    @Override
    public Boolean getOriginalValue() {
        return originalValue;
    }

    @Override
    public void setOriginalValue(Boolean originalValue) {
        this.originalValue = originalValue;
    }

    @Override
    protected void createRandomModification() {
        VariableModification<Boolean> vm = BooleanModificationFactory.createRandomModification();
        setModification(vm);
    }

    @Override
    public boolean isOriginalValueModified() {
        return getOriginalValue() != null && (getOriginalValue().compareTo(getValue()) != 0);
    }

    @Override
    public boolean validateAssertions() {
        if (assertEquals != null) {
            if (assertEquals.compareTo(getValue()) != 0) {
                return false;
            }
        }
        return true;
    }
}
