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
@XmlType(propOrder = { "subtrahend", "modificationFilter", "postModification" })
public class LongSubtractModification extends VariableModification<Long> {

    private Long subtrahend;

    public LongSubtractModification() {

    }

    public LongSubtractModification(Long bi) {
        this.subtrahend = bi;
    }

    @Override
    protected Long modifyImplementationHook(final Long input) {
        return (input == null) ? -subtrahend : input - subtrahend;
    }

    public Long getSubtrahend() {
        return subtrahend;
    }

    public void setSubtrahend(Long subtrahend) {
        this.subtrahend = subtrahend;
    }
}
