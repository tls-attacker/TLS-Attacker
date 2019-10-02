/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.connection.Aliasable;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.Serializable;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * TlsAction that can be executed in a WorkflowTrace. The TlsAction is the basic
 * building block for WorkflowTraces. A WorkflowTrace is a list of TLSActions.
 * Executing a WorkflowTrace means iterating through this list and calling
 * execute() on each TlsAction.
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class TlsAction implements Serializable, Aliasable {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final boolean EXECUTED_DEFAULT = false;

    private Boolean executed = null;

    // Whether the action is executed in a workflow with a single connection
    // or not. Useful to decide which information can be stripped in filter().
    @XmlTransient
    private Boolean singleConnectionWorkflow = true;

    @XmlTransient
    private final Set<String> aliases = new LinkedHashSet<>();

    public TlsAction() {
    }

    public boolean isExecuted() {
        if (executed == null) {
            return EXECUTED_DEFAULT;
        }
        return executed;
    }

    public void setExecuted(Boolean executed) {
        this.executed = executed;
    }

    public Boolean isSingleConnectionWorkflow() {
        return singleConnectionWorkflow;
    }

    public void setSingleConnectionWorkflow(Boolean singleConnectionWorkflow) {
        this.singleConnectionWorkflow = singleConnectionWorkflow;
    }

    public abstract void execute(State state) throws WorkflowExecutionException;

    public abstract void reset();

    /**
     * Add default values and initialize empty fields.
     */
    public void normalize() {
        // We don't need any defaults
    }

    /**
     * Add default values from given defaultAction and initialize empty fields.
     *
     * @param defaultAction
     *            Not needed / not evaluated
     */
    public void normalize(TlsAction defaultAction) {
        // We don't need any defaults
    }

    /**
     * Filter empty fields and default values.
     */
    public void filter() {
    }

    /**
     * Filter empty fields and default values given in defaultAction.
     *
     * @param defaultAction
     *            Not needed / not evaluated
     */
    public void filter(TlsAction defaultAction) {
    }

    @Override
    public String getFirstAlias() {
        return getAllAliases().iterator().next();
    }

    @Override
    public boolean containsAllAliases(Collection<String> aliases) {
        return getAllAliases().containsAll(aliases);
    }

    ;

    @Override
    public boolean containsAlias(String alias) {
        return getAllAliases().contains(alias);
    }

    ;

    @Override
    public void assertAliasesSetProperly() throws ConfigurationException {
    }

    @Override
    public Set<String> getAllAliases() {
        return aliases;
    }

    /**
     * Check that the Action got executed as planned.
     *
     * @return True if the Action executed as planned
     */
    public abstract boolean executedAsPlanned();

    public boolean isMessageAction() {
        return this instanceof MessageAction;
    }

    @Override
    public String aliasesToString() {
        StringBuilder sb = new StringBuilder();
        for (String alias : getAllAliases()) {
            sb.append(alias).append(",");
        }
        sb.deleteCharAt(sb.lastIndexOf(","));
        return sb.toString();
    }

    public String toCompactString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getClass().getSimpleName());
        if (!getAllAliases().isEmpty()) {
            sb.append(" [").append(aliasesToString()).append("]");
        }
        return sb.toString();
    }

}
