/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.connection;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.util.Collection;
import java.util.Set;

/**
 * Provide common alias methods for TLS context/connection bound objects. TLS contexts are
 * referenced by the alias of their connections. Objects implementing this interface provide a
 * uniform way to access aliases that identify the connections they belong to.
 */
public interface Aliasable {
    void assertAliasesSetProperly() throws ConfigurationException;

    String aliasesToString();

    String getFirstAlias();

    Set<String> getAllAliases();

    boolean containsAlias(String alias);

    boolean containsAllAliases(Collection<String> aliases);
}
