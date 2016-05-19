/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.singlebyte;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlType(propOrder = { "explicitValue", "modificationFilter", "postModification" })
public class ByteExplicitValueModification extends VariableModification<Byte> {

    private Byte explicitValue;

    public ByteExplicitValueModification() {

    }

    public ByteExplicitValueModification(Byte bi) {
	this.explicitValue = bi;
    }

    @Override
    protected Byte modifyImplementationHook(final Byte input) {
	return explicitValue;
    }

    public Byte getExplicitValue() {
	return explicitValue;
    }

    public void setExplicitValue(Byte explicitValue) {
	this.explicitValue = explicitValue;
    }
}
