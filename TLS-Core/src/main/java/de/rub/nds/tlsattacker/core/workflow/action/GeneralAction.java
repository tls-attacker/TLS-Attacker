/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * An action that can be used for testing or to provide defaults for the filter/ normalize methods.
 */
@XmlRootElement
public class GeneralAction extends TlsAction {

    @XmlTransient private final Set<String> aliases = new LinkedHashSet<>();

    public GeneralAction() {}

    public GeneralAction(String alias) {
        this.aliases.add(alias);
    }

    public GeneralAction(Collection aliases) {
        this.aliases.addAll(aliases);
    }

    public GeneralAction(String... aliases) {
        this.aliases.addAll(Arrays.asList(aliases));
    }

    @Override
    public Set<String> getAllAliases() {
        return aliases;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reset() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void normalize() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void normalize(TlsAction defaultAction) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void filter() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void filter(TlsAction defaultAction) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean executedAsPlanned() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
