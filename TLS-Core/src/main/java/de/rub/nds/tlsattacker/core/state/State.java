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
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;

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

 */
public class State {

    protected static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(State.class.getName());

    private Config config = null;

    /**
     * All TLS contexts required for workflow execution. These map is managed
     * automatically based on the connection ends defined in the workflow trace.
     * Should not be set manually.
     */
    private final Map<String, TlsContext> tlsContexts = new HashMap<>();

    /**
     * A listening (also accepting) TLS context is a context with a server
     * socket on our side. Should not be set manually.
     */
    private final List<TlsContext> listeningTlsContexts = new ArrayList<>();

    /**
     * A connecting TLS context is a context which holds a connection
     * established from our side to a remote server. Should not be set manually.
     */
    private final List<TlsContext> connectingTlsContexts = new ArrayList<>();

    @HoldsModifiableVariable
    private WorkflowTrace workflowTrace = null;

    public State() {
        this(Config.createConfig());
    }

    public State(Config config) {
        this.config = config;
    }

    public State(Config config, WorkflowTrace trace) {
        this.config = config;
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
        if (!tlsContexts.isEmpty()) {
            LOGGER.debug("Setting new workflow trace, clearing old contexts.");
            clearTlsContexts();
        }
        if (trace.getConnectionEnds() == null) {
            LOGGER.debug("Workflow trace does not define any connection ends. "
                    + "Adding connection end(s) from default config");
            trace.setConnectionEnds(config.getConnectionEnds());
        }
        List<ConnectionEnd> conEnds = trace.getConnectionEnds();

        if (conEnds.size() == 1) {
            ConnectionEnd conEnd = conEnds.get(0);
            TlsContext ctx = new TlsContext(config, conEnd);
            if (conEnd.getAlias() == null) {
                LOGGER.debug("Missing connection end alias in workflow trace, using default" + " alias ("
                        + config.DEFAULT_CONNECTION_END_ALIAS + ").");
                conEnd.setAlias(config.DEFAULT_CONNECTION_END_ALIAS);
            }
            addTlsContext(ctx);
        } else {
            for (ConnectionEnd conEnd : conEnds) {
                TlsContext ctx = new TlsContext(config, conEnd);
                addTlsContext(ctx);
            }
        }
        this.workflowTrace = trace;
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
     * @see getTlsContext(String)
     */
    public TlsContext getTlsContext() {
        if (tlsContexts.isEmpty()) {
            if (workflowTrace == null) {
                throw new ConfigurationException("No context defined, perhaps because no"
                        + " workflow trace is loaded yet.");
            }
            throw new ConfigurationException("No context defined.");
        }
        if (tlsContexts.size() > 1) {
            throw new ConfigurationException("getTlsContext requires an alias if multiple contexts are defined");
        }
        return tlsContexts.entrySet().iterator().next().getValue();
    }

    /**
     * Get TLS context with given alias. Aliases are the ones assigned to the
     * corresponding connection ends.
     * 
     * @return the context with the given connection end alias
     * @see convenience method for single context states: getTlsContext()
     */
    public TlsContext getTlsContext(String alias) {
        if (tlsContexts.get(alias) == null) {
            throw new ConfigurationException("No context defined with alias '" + alias + "'.");
        }
        return tlsContexts.get(alias);
    }

    public Map<String, TlsContext> getTlsContexts() {
        return Collections.unmodifiableMap(tlsContexts);
    }

    public List<TlsContext> getListeningTlsContexts() {
        return Collections.unmodifiableList(listeningTlsContexts);
    }

    public List<TlsContext> getConnectingTlsContexts() {
        return Collections.unmodifiableList(connectingTlsContexts);
    }

    public Config getConfig() {
        return config;
    }

    private void addTlsContext(TlsContext context) {
        ConnectionEnd conEnd = context.getConnectionEnd();
        String alias = conEnd.getAlias();
        if (alias == null) {
            throw new ConfigurationException("Connection end alias not set (null). Can't add the TLS context.");
        }
        if (tlsContexts.containsKey(alias)) {
            throw new ConfigurationException("Connection end alias already in use: " + alias);
        }

        LOGGER.debug("Adding context " + alias);
        tlsContexts.put(alias, context);

        if (conEnd.getConnectionEndType() == ConnectionEndType.SERVER) {
            LOGGER.trace("Adding context " + alias + " to listeningCtxs");
            listeningTlsContexts.add(context);
        } else {
            LOGGER.trace("Adding context " + alias + " to connectingCtxs");
            connectingTlsContexts.add(context);
        }
    }

    private void clearTlsContexts() {
        LOGGER.debug("Clearing contexts from state");
        tlsContexts.clear();
        listeningTlsContexts.clear();
        connectingTlsContexts.clear();

        LOGGER.debug("Removing connection ends from workflow trace");
        if (workflowTrace != null) {
            workflowTrace.clearConnectionEnds();
        }
    }

}
