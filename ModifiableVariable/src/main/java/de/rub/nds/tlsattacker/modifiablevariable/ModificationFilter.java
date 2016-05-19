/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable;

import de.rub.nds.tlsattacker.modifiablevariable.filter.AccessModificationFilter;
import javax.xml.bind.annotation.XmlSeeAlso;

/**
 * It is possible to filter modifications only for specific number of data
 * accesses or specific data. For example, only the first data access returns a
 * modified value. This can be achieved using a ModificationFilter object.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlSeeAlso({ AccessModificationFilter.class })
public abstract class ModificationFilter {

    public abstract boolean filterModification();
}
