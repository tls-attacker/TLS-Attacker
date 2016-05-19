/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.biginteger;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import java.math.BigInteger;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlType(propOrder = { "subtrahend", "modificationFilter", "postModification" })
public class BigIntegerSubtractModification extends VariableModification<BigInteger> {

    private BigInteger subtrahend;

    public BigIntegerSubtractModification() {

    }

    public BigIntegerSubtractModification(BigInteger bi) {
	this.subtrahend = bi;
    }

    @Override
    protected BigInteger modifyImplementationHook(BigInteger input) {
	if (input == null) {
	    input = BigInteger.ZERO;
	}
	return input.subtract(subtrahend);
    }

    public BigInteger getSubtrahend() {
	return subtrahend;
    }

    public void setSubtrahend(BigInteger subtrahend) {
	this.subtrahend = subtrahend;
    }
}
