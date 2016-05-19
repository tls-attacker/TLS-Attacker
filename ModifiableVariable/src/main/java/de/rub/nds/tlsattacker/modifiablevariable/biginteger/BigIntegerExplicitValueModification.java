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
@XmlType(propOrder = { "explicitValue", "modificationFilter", "postModification" })
public class BigIntegerExplicitValueModification extends VariableModification<BigInteger> {

    private BigInteger explicitValue;

    public BigIntegerExplicitValueModification() {

    }

    public BigIntegerExplicitValueModification(BigInteger bi) {
	this.explicitValue = bi;
    }

    @Override
    protected BigInteger modifyImplementationHook(final BigInteger input) {
	return explicitValue;
    }

    public BigInteger getExplicitValue() {
	return explicitValue;
    }

    public void setExplicitValue(BigInteger explicitValue) {
	this.explicitValue = explicitValue;
    }
}
