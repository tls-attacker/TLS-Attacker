/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.socket.AliasedConnection;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The central object passed around during program execution. The state
 * initializes and holds the workflow trace, the default configuration and the
 * corresponding TLS contexts.
 *
 * <p>
 * The concept behind this class is as follows: the state is initialized with
 * the user configured values, that is, via default configuration and a given
 * workflow trace (type). On initialization, the state will create the necessary
 * TLS contexts for workflow execution. These contexts should be considered as
 * dynamic objects, representing TLS connections, calculations and other data
 * exchanged during the TLS actual workflow execution.
 * <p>
 * 
 * <p>
 * Therefore, there is no interface for setting TLS contexts manually. They are
 * always automatically created based on the connection ends defined in the
 * workflow trace.
 * <p>
 * 
 * <p>
 * Please also have a look at the tests supplied with this class for some
 * initialization examples with expected behavior.
 * </p>
 * 
 * 
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class State {

    protected static final Logger LOGGER = LogManager.getLogger(State.class.getName());

    private Config config = null;
    private ContextContainer contextContainer = new ContextContainer();
    private RunningModeType runningMode = null;

    @HoldsModifiableVariable
    private WorkflowTrace workflowTrace = null;

    public State() {
        this(Config.createConfig());
    }

    public State(Config config) {
        this.config = config;
        runningMode = config.getDefaulRunningMode();
    }

    public State(Config config, WorkflowTrace trace) {
        this.config = config;
        runningMode = config.getDefaulRunningMode();
        setWorkflowTrace(trace);
    }

    /**
     * Set a new workflow trace. Existing TLS contexts are discarded and fresh
     * contexts are initialized based on the config and the given connection
     * ends in the trace. If the trace does not define any connection ends,
     * default values are loaded from config, if any.
     * 
     * @param trace
     *            The workflow trace to execute.
     */
    public final void setWorkflowTrace(WorkflowTrace trace) {
        if (!contextContainer.isEmpty()) {
            LOGGER.debug("Setting new workflow trace, clearing old contexts (if any)");
            contextContainer.clear();
        }

        WorkflowTraceUtil.mixInDefaultsForExecution(trace, config, runningMode);

        for (AliasedConnection con : trace.getConnections()) {
            TlsContext ctx = new TlsContext(config, con);
            addTlsContext(ctx);
        }
        this.workflowTrace = trace;
    }

    public Config getConfig() {
        return config;
    }

    public WorkflowTrace getWorkflowTrace() {
        return workflowTrace;
    }

    /**
     * Use this convenience method when working with a single context only. It
     * should be used only if there is exactly one context defined in the state.
     * This would typically be the default context as defined in the config.
     * 
     * @return the only context known to the state
     * @see this.getTlsContext(String)
     */
    public TlsContext getTlsContext() {
        assertWorkflowTraceNotNull("getTlsContext");
        return contextContainer.getTlsContext();
    }

    /**
     * Get TLS context with given alias. Aliases are the ones assigned to the
     * corresponding connection ends.
     * 
     * @return the context with the given connection end alias
     * @see convenience method for single context states: getTlsContext()
     */
    public TlsContext getTlsContext(String alias) {
        assertWorkflowTraceNotNull("getTlsContext");
        return contextContainer.getTlsContext(alias);
    }

    public List<TlsContext> getAllTlsContexts() {
        assertWorkflowTraceNotNull("getAllTlsContexts");
        return contextContainer.getAllContexts();
    }

    public List<TlsContext> getInboundTlsContexts() {
        assertWorkflowTraceNotNull("getInboundTlsContexts");
        return contextContainer.getInboundTlsContexts();
    }

    public List<TlsContext> getOutboundTlsContexts() {
        assertWorkflowTraceNotNull("getOutboundTlsContexts");
        return contextContainer.getOutboundTlsContexts();
    }

    public RunningModeType getRunningMode() {
        return runningMode;
    }

    public void setRunningMode(RunningModeType runningMode) {
        this.runningMode = runningMode;
    }

    private void addTlsContext(TlsContext context) {
        contextContainer.addTlsContext(context);
    }

    private void assertWorkflowTraceNotNull(String operation_name) {
        if (workflowTrace != null) {
            return;
        }

        StringBuilder err = new StringBuilder("No workflow trace loaded.");
        if (operation_name != null && !operation_name.isEmpty()) {
            err.append(" Operation ").append(operation_name).append(" not permitted");
        }
        throw new ConfigurationException(err.toString());
    }
}
