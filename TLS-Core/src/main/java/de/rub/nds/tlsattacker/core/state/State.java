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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceNormalizer;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.filter.Filter;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterFactory;
import de.rub.nds.tlsattacker.core.workflow.filter.FilterType;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Random;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
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
 * </p>
 *
 * <p>
 * Therefore, there is no public interface for setting TLS contexts manually.
 * They are always automatically created based on the connections defined in the
 * workflow trace.
 * </p>
 *
 * <p>
 * Please also have a look at the tests supplied with this class for some
 * initialization examples with expected behavior.
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

    public State() {
        this(Config.createConfig());
    }

    public State(WorkflowTrace trace) {
        this(Config.createConfig(), trace);
    }

    public State(Config config) {
        this.config = config;
        runningMode = config.getDefaultRunningMode();
        this.workflowTrace = loadWorkflowTrace();
        initState();
    }

    public State(Config config, WorkflowTrace workflowTrace) {
        this.config = config;
        runningMode = config.getDefaultRunningMode();
        this.workflowTrace = workflowTrace;
        initState();
    }

    public void reset() {
        contextContainer.clear();
        workflowTrace.reset();
        initState();
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
        WorkflowTrace trace = null;

        if (config.getWorkflowInput() != null) {
            try {
                trace = WorkflowTraceSerializer.read(new FileInputStream(new File(config.getWorkflowInput())));
                LOGGER.debug("Loaded workflow trace from " + config.getWorkflowInput());
            } catch (FileNotFoundException ex) {
                LOGGER.warn("Could not read workflow trace. File not found: " + config.getWorkflowInput());
                LOGGER.debug(ex);
            } catch (JAXBException | IOException | XMLStreamException ex) {
                LOGGER.warn("Could not read workflow trace: " + config.getWorkflowInput());
                LOGGER.debug(ex);
            }
        } else if (config.getWorkflowTraceType() != null) {
            WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
            trace = factory.createWorkflowTrace(config.getWorkflowTraceType(), runningMode);
            LOGGER.debug("Created new " + config.getWorkflowTraceType() + " workflow trace");
        }

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
     * Replace existing TlsContext with new TlsContext. This can only be done if
     * existingTlsContext.connection equals newTlsContext.connection.
     *
     * @param newTlsContext
     *            The new TlsContext to replace the old with
     */
    public void replaceTlsContext(TlsContext newTlsContext) {
        contextContainer.replaceTlsContext(newTlsContext);
    }

    /**
     * Use this convenience method when working with a single context only. It
     * should be used only if there is exactly one context defined in the state.
     * This would typically be the default context as defined in the config.
     *
     * Note: Be careful when changing the context. I.e. if you change it's
     * connection, the state can get out of sync.
     *
     * TODO: Ideally, this would return a deep copy to prevent State
     * invalidation.
     *
     * @return the only context known to the state
     */
    public TlsContext getTlsContext() {
        return contextContainer.getTlsContext();
    }

    /**
     * Get TLS context with given alias. Aliases are the ones assigned to the
     * corresponding connection ends.
     *
     * Note: Be careful when changing the context. I.e. if you change it's
     * connection, the state can get out of sync.
     *
     * TODO: Ideally, this would return a deep copy to prevent State
     * invalidation.
     *
     *
     * @param alias
     *            The Alias for which the TLSContext should be returned
     *
     * @return the context with the given connection end alias
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
     * Return a filtered copy of the given workflow trace. This method does not
     * modify the input trace.
     *
     * @param trace
     *            The workflow trace that should be filtered
     * @return A filtered copy of the input workflow trace
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
     *            The workflow trace that should be filtered
     */
    private void filterTrace(WorkflowTrace trace) {
        List<FilterType> filters = config.getOutputFilters();
        if ((filters == null) || (filters.isEmpty())) {
            LOGGER.debug("No filters to apply, ouput filter list is empty");
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

    /**
     * Serialize and write states workflow trace to file.
     */
    public void storeTrace() {
        assertWorkflowTraceNotNull("storeTrace");

        Random random = new Random();
        if (config.getWorkflowOutput() != null && !config.getWorkflowOutput().isEmpty()) {
            try {
                File f = new File(config.getWorkflowOutput());
                if (f.isDirectory()) {
                    f = new File(config.getWorkflowOutput() + "trace-" + random.nextInt());
                }
                WorkflowTrace filteredTrace;
                if (config.isApplyFiltersInPlace()) {
                    filteredTrace = workflowTrace;
                    filterTrace(filteredTrace);
                } else {
                    filteredTrace = getFilteredTraceCopy(workflowTrace);
                }
                WorkflowTraceSerializer.write(f, filteredTrace);
            } catch (JAXBException | IOException ex) {
                LOGGER.info("Could not serialize WorkflowTrace.");
                LOGGER.debug(ex);
            }
        }
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
