/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

/**
 * Copy the value of a given field from one context to another.
 */
@XmlType(propOrder = { "srcConnectionAlias", "dstConnectionAlias" })
public abstract class CopyContextFieldAction extends TlsAction {

    @XmlElement(name = "from")
    private String srcConnectionAlias;
    @XmlElement(name = "to")
    private String dstConnectionAlias;

    public CopyContextFieldAction() {
    }

    public CopyContextFieldAction(String srcConnectionAlias, String dstConnectionAlias) {
        this.srcConnectionAlias = srcConnectionAlias;
        this.dstConnectionAlias = dstConnectionAlias;
    }

    /**
     * Invoked on action execution to perform the actual copy operation.
     * 
     * @param srcContext
     *            source context
     * @param dstContext
     *            destination context
     */
    protected abstract void copyField(TlsContext srcContext, TlsContext dstContext);

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        if ((srcConnectionAlias == null) || (dstConnectionAlias == null)) {
            throw new WorkflowExecutionException("Cannot execute at least one context alias is null!");
        }

        TlsContext src = state.getTlsContext(srcConnectionAlias);
        TlsContext dst = state.getTlsContext(dstConnectionAlias);

        copyField(src, dst);
        setExecuted(true);
    }

    public String getSrcContextAlias() {
        return srcConnectionAlias;
    }

    public String getDstContextAlias() {
        return dstConnectionAlias;
    }

    @Override
    public void reset() {
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 53 * hash + Objects.hashCode(this.srcConnectionAlias);
        hash = 53 * hash + Objects.hashCode(this.dstConnectionAlias);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CopyContextFieldAction other = (CopyContextFieldAction) obj;
        if (!Objects.equals(this.srcConnectionAlias, other.srcConnectionAlias)) {
            return false;
        }
        return Objects.equals(this.dstConnectionAlias, other.dstConnectionAlias);
    }

    @Override
    public Set<String> getAllAliases() {
        Set<String> aliases = new LinkedHashSet<>();
        aliases.add(srcConnectionAlias);
        aliases.add(dstConnectionAlias);
        return aliases;
    }

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
        if ((srcConnectionAlias == null) || (srcConnectionAlias.isEmpty())) {
            throw new WorkflowExecutionException("Can't execute " + this.getClass().getSimpleName()
                    + " with empty src alias (if using XML: add <from/>)");
        }
        if ((dstConnectionAlias == null) || (dstConnectionAlias.isEmpty())) {
            throw new WorkflowExecutionException("Can't execute " + this.getClass().getSimpleName()
                    + " with empty dst alias (if using XML: add <to/>)");
        }
    }
}
