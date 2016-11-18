/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.integer;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlType(propOrder = { "explicitValue", "modificationFilter", "postModification" })
public class IntegerExplicitValueModification extends VariableModification<Integer> {

    private Integer explicitValue;

    public IntegerExplicitValueModification() {

    }

    public IntegerExplicitValueModification(Integer bi) {
        this.explicitValue = bi;
    }

    @Override
    protected Integer modifyImplementationHook(final Integer input) {
        return explicitValue;
    }

    public Integer getExplicitValue() {
        return explicitValue;
    }

    public void setExplicitValue(Integer explicitValue) {
        this.explicitValue = explicitValue;
    }
}
