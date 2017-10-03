/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.util.Collection;
import java.util.Set;

/**
 * Provide common alias methods for TLS context aware objects. TLS contexts are
 * referenced by alias. Objects implementing the Aliasable interface provide a
 * uniform way to access aliases that identify the TLS contexts the objects
 * belong to.
 * 
 * @author Lucas Hartmann - lucas.hartmann@rub.de
 */
public interface Aliasable {
    public abstract void assertAliasesSetProperly() throws ConfigurationException;

    public abstract String aliasesToString();

    public abstract String getFirstAlias();

    public abstract Set<String> getAllAliases();

    public abstract boolean containsAlias(String alias);

    public abstract boolean containsAllAliases(Collection<? extends String> aliases);
}