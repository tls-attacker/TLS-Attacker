/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.mlong;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlType(propOrder = { "xor", "modificationFilter", "postModification" })
public class LongXorModification extends VariableModification<Long> {

    private Long xor;

    public LongXorModification() {

    }

    public LongXorModification(Long bi) {
        this.xor = bi;
    }

    @Override
    protected Long modifyImplementationHook(final Long input) {
        return (input == null) ? xor : input ^ xor;
    }

    public Long getXor() {
        return xor;
    }

    public void setXor(Long xor) {
        this.xor = xor;
    }
}
