/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceNormalizer;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.filter.Filter;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterFactory;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterType;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The central object passed around during program execution. The state initializes and holds the workflow trace, the
 * default configuration and the corresponding TLS contexts.
 *
 * <p>
 * The concept behind this class is as follows: the state is initialized with the user configured values, that is, via
 * default configuration and a given workflow trace (type). On initialization, the state will create the necessary TLS
 * contexts for workflow execution. These contexts should be considered as dynamic objects, representing TLS
 * connections, calculations and other data exchanged during the TLS actual workflow execution.
 * </p>
 *
 * <p>
 * Therefore, there is no public interface for setting TLS contexts manually. They are always automatically created
 * based on the connections defined in the workflow trace.
 * </p>
 *
 * <p>
 * Please also have a look at the tests supplied with this class for some initialization examples with expected
 * behavior.
 * </p>
 *
 */
public class State {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ContextContainer contextContainer = new ContextContainer();
    private Config config = null;
    private RunningModeType runningMode = null;

    @HoldsModifiableVariable
    private final WorkflowTrace workflowTrace;
    private WorkflowTrace originalWorkflowTrace;

    private long startTimestamp;
    private long endTimestamp;
    private Throwable executionException;

    private LinkedList<Process> spawnedSubprocesses;

    public State() {
        this(Config.createConfig());
    }

    public State(WorkflowTrace trace) {
        this(Config.createConfig(), trace);
    }

    public State(Config config) {
        this.config = config;
        runningMode = config.getDefaultRunningMode();
        spawnedSubprocesses = new LinkedList<>();
        this.workflowTrace = loadWorkflowTrace();
        initState();
    }

    public State(Config config, WorkflowTrace workflowTrace) {
        this.config = config;
        runningMode = config.getDefaultRunningMode();
        spawnedSubprocesses = new LinkedList<>();
        this.workflowTrace = workflowTrace;
        initState();
    }

    public void reset() {
        List<TlsContext> previousContexts = contextContainer.getAllContexts();
        contextContainer.clear();
        workflowTrace.reset();
        killAllSpawnedSubprocesses();
        initState();
        retainServerTcpTransportHandlers(previousContexts);
    }

    private void retainServerTcpTransportHandlers(List<TlsContext> previousContexts) {
        previousContexts.forEach(oldContext -> {
            if (oldContext.getTransportHandler() != null
                && oldContext.getTransportHandler() instanceof ServerTcpTransportHandler) {
                contextContainer.getTlsContext(oldContext.getConnection().getAlias())
                    .setTransportHandler(oldContext.getTransportHandler());
            }
        });
    }

    /**
     * Normalize trace and initialize TLS contexts.
     */
    public final void initState() {
        // Keep a snapshot to restore user defined trace values after filtering.
        if (config.isFiltersKeepUserSettings()) {
            originalWorkflowTrace = WorkflowTrace.copy(workflowTrace);
        }

        WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
        normalizer.normalize(workflowTrace, config, runningMode);
        workflowTrace.setDirty(false);

        for (AliasedConnection con : workflowTrace.getConnections()) {
            TlsContext ctx = new TlsContext(config, con);
            addTlsContext(ctx);
        }
    }

    private WorkflowTrace loadWorkflowTrace() {
        if (config.getWorkflowTraceType() == null) {
            throw new ConfigurationException("Could not load workflow trace, type is null");
        }
        WorkflowTrace trace;

        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        trace = factory.createWorkflowTrace(config.getWorkflowTraceType(), runningMode);
        LOGGER.debug("Created new " + config.getWorkflowTraceType() + " workflow trace");

        if (trace == null) {
            throw new ConfigurationException("Could not load workflow trace");
        }
        return trace;
    }

    public Config getConfig() {
        return config;
    }

    public WorkflowTrace getWorkflowTrace() {
        return workflowTrace;
    }

    public WorkflowTrace getOriginalWorkflowTrace() {
        return originalWorkflowTrace;
    }

    /**
     * Replace existing TlsContext with new TlsContext. This can only be done if existingTlsContext.connection equals
     * newTlsContext.connection.
     *
     * @param newTlsContext
     *                      The new TlsContext to replace the old with
     */
    public void replaceTlsContext(TlsContext newTlsContext) {
        contextContainer.replaceTlsContext(newTlsContext);
    }

    /**
     * Use this convenience method when working with a single context only. It should be used only if there is exactly
     * one context defined in the state. This would typically be the default context as defined in the config.
     *
     * Note: Be careful when changing the context. I.e. if you change it's connection, the state can get out of sync.
     *
     * TODO: Ideally, this would return a deep copy to prevent State invalidation.
     *
     * @return the only context known to the state
     */
    public TlsContext getTlsContext() {
        return contextContainer.getTlsContext();
    }

    /**
     * Get TLS context with given alias. Aliases are the ones assigned to the corresponding connection ends.
     *
     * Note: Be careful when changing the context. I.e. if you change it's connection, the state can get out of sync.
     *
     * TODO: Ideally, this would return a deep copy to prevent State invalidation.
     *
     *
     * @param  alias
     *               The Alias for which the TLSContext should be returned
     *
     * @return       the context with the given connection end alias
     */
    public TlsContext getTlsContext(String alias) {
        return contextContainer.getTlsContext(alias);
    }

    public List<TlsContext> getAllTlsContexts() {
        return contextContainer.getAllContexts();
    }

    public List<TlsContext> getInboundTlsContexts() {
        return contextContainer.getInboundTlsContexts();
    }

    public List<TlsContext> getOutboundTlsContexts() {
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

    /**
     * Get state's (normalized) workflow trace.
     *
     * @return a copy of the state's (normalized) workflow trace
     */
    public WorkflowTrace getWorkflowTraceCopy() {
        return WorkflowTrace.copy(workflowTrace);
    }

    /**
     * Get a filtered copy of the state's workflow trace.
     *
     * @return a filtered copy of the input workflow trace
     */
    public WorkflowTrace getFilteredTraceCopy() {
        return getFilteredTraceCopy(workflowTrace);
    }

    /**
     * Return a filtered copy of the given workflow trace. This method does not modify the input trace.
     *
     * @param  trace
     *               The workflow trace that should be filtered
     * @return       A filtered copy of the input workflow trace
     */
    private WorkflowTrace getFilteredTraceCopy(WorkflowTrace trace) {
        WorkflowTrace filtered = WorkflowTrace.copy(trace);
        filterTrace(filtered);
        return filtered;
    }

    /**
     * Apply filters to trace in place.
     *
     * @param trace
     *              The workflow trace that should be filtered
     */
    private void filterTrace(WorkflowTrace trace) {
        List<FilterType> filters = config.getOutputFilters();
        if ((filters == null) || (filters.isEmpty())) {
            LOGGER.debug("No filters to apply, output filter list is empty");
            return;
        }
        // Filters contains null if set loaded from -config with entry
        // <outputFilters/>.
        if (filters.contains(null)) {
            LOGGER.debug("No filters to apply");
            return;
        }
        for (FilterType filterType : config.getOutputFilters()) {
            Filter filter = FilterFactory.createWorkflowTraceFilter(filterType, config);
            filter.applyFilter(trace);
            if (config.isFiltersKeepUserSettings()) {
                filter.postFilter(trace, originalWorkflowTrace);
            }
        }
    }

    private void assertWorkflowTraceNotNull(String operationName) {
        if (workflowTrace != null) {
            return;
        }

        StringBuilder err = new StringBuilder("No workflow trace loaded.");
        if (operationName != null && !operationName.isEmpty()) {
            err.append(" Operation ").append(operationName).append(" not permitted");
        }
        throw new ConfigurationException(err.toString());
    }

    public long getStartTimestamp() {
        return startTimestamp;
    }

    public void setStartTimestamp(long startTimestamp) {
        this.startTimestamp = startTimestamp;
    }

    public long getEndTimestamp() {
        return endTimestamp;
    }

    public void setEndTimestamp(long endTimestamp) {
        this.endTimestamp = endTimestamp;
    }

    public Throwable getExecutionException() {
        return executionException;
    }

    public void setExecutionException(Throwable executionException) {
        this.executionException = executionException;
    }

    /**
     * Records a process that was spawned during this state execution.
     *
     * @param process
     *                The process to record
     */
    public void addSpawnedSubprocess(Process process) {
        if (process != null) {
            spawnedSubprocesses.add(process);
        }
    }

    /**
     * Kills all recorded processes that have been spawned during this state execution.
     */
    public void killAllSpawnedSubprocesses() {
        for (Process process : spawnedSubprocesses) {
            process.destroy();
        }

        spawnedSubprocesses.clear();
    }
}
