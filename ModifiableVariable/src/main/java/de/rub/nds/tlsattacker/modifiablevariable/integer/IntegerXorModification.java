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
@XmlType(propOrder = { "xor", "modificationFilter", "postModification" })
public class IntegerXorModification extends VariableModification<Integer> {

    private Integer xor;

    public IntegerXorModification() {

    }

    public IntegerXorModification(Integer bi) {
	this.xor = bi;
    }

    @Override
    protected Integer modifyImplementationHook(final Integer input) {
	return (input == null) ? xor : input ^ xor;
    }

    public Integer getXor() {
	return xor;
    }

    public void setXor(Integer xor) {
	this.xor = xor;
    }
}
