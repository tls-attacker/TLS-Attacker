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
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class State {

    protected static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(State.class.getName());

    private Config config = null;

    private final Map<String, TlsContext> tlsContexts = new HashMap<>();

    /**
     * A listening TLS context is a context with a server socket on our side.
     * This list is managed automatically and should be accessed for reading
     * only.
     */
    private final List<TlsContext> listeningTlsContexts = new ArrayList<>();

    /**
     * A connecting TLS context is a context which holds a connection
     * established from our side to a remote server. This list is managed
     * automatically and should be accessed for reading only.
     */
    private final List<TlsContext> connectingTlsContexts = new ArrayList<>();

    /**
     * Trace of all messages exchanged during the communication.
     */
    @HoldsModifiableVariable
    private WorkflowTrace workflowTrace = null;

    public State() {
        this(Config.createConfig());
    }

    public State(Config config) {
        this.config = config;
        // WIP config.getConnectionEnds() should never be empty. It should
        // either contain custom connection ends or the default
        // connection end.
        List<ConnectionEnd> conEnds = config.getConnectionEnds();
        if ((conEnds == null) || (conEnds.isEmpty())) {
            TlsContext ctx = new TlsContext(config);
            addTlsContext(Config.DEFAULT_CONTEXT_ALIAS, ctx);
        } else {
            for (ConnectionEnd conEnd : conEnds) {
                TlsContext ctx = new TlsContext(config);
                ctx.setConnectionEndType(conEnd.getConnectionEndType());
                ctx.setHost(conEnd.getHostname());
                ctx.setPort(conEnd.getPort());
                addTlsContext(conEnd.getAlias(), ctx);
            }
        }
    }

    public WorkflowTrace getWorkflowTrace() {
        return workflowTrace;
    }

    public void setWorkflowTrace(WorkflowTrace workflowTrace) {
        this.workflowTrace = workflowTrace;
    }

    public void clearTlsContexts() {
        tlsContexts.clear();
        listeningTlsContexts.clear();
        connectingTlsContexts.clear();
    }

    /**
     * Use this convenience method when working with a single context only. It
     * should be used only if there is exactly one context defined in the state.
     * 
     * @return the context known to the state (usually the default context)
     */
    public TlsContext getTlsContext() {
        if (tlsContexts.isEmpty()) {
            throw new ConfigurationException("No context defined");
        }
        if (tlsContexts.size() > 1) {
            throw new ConfigurationException("getTlsContext requires an alias if multiple contexts are defined");
        }

        return tlsContexts.entrySet().iterator().next().getValue();
    }

    public TlsContext getTlsContext(String alias) {
        if (tlsContexts.get(alias) == null) {
            throw new ConfigurationException("No context defined with alias '" + alias + "'.");
        }
        return tlsContexts.get(alias);
    }

    public Map<String, TlsContext> getTlsContexts() {
        return Collections.unmodifiableMap(tlsContexts);
    }

    public final void addTlsContext(String alias, TlsContext context) {

        if (tlsContexts.containsKey(alias)) {
            throw new ConfigurationException("Alias already in use: " + alias);
        }
        LOGGER.info("Adding context " + alias);
        tlsContexts.put(alias, context);
        context.setAlias(alias);
        if (context.getConnectionEndType() == ConnectionEndType.SERVER) {
            LOGGER.debug("Adding context " + alias + " to listeningCtxs");
            listeningTlsContexts.add(context);
        } else {
            LOGGER.debug("Adding context " + alias + " to connectingCtxs");
            connectingTlsContexts.add(context);
        }
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

}
