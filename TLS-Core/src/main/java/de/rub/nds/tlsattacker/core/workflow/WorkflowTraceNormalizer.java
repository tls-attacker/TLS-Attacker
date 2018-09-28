/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.action.GeneralAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Builds a "normalized" workflow trace.
 */
public class WorkflowTraceNormalizer {

    private static final Logger LOGGER = LogManager.getLogger();

    public void normalize(WorkflowTrace trace, Config config) {
        normalize(trace, config, config.getDefaultRunningMode());
    }

    /**
     * Merge in default values from Config if necessary.
     *
     * @param trace
     *            The trace that should be normalized
     * @param config
     *            The config that is used
     * @param mode
     *            The mode the Trace is ran in
     */
    public void normalize(WorkflowTrace trace, Config config, RunningModeType mode) {
        List<AliasedConnection> traceConnections = trace.getConnections();
        InboundConnection defaultInCon = config.getDefaultServerConnection().getCopy();
        OutboundConnection defaultOutCon = config.getDefaultClientConnection().getCopy();

        if (traceConnections == null) {
            traceConnections = new ArrayList<>();
            trace.setConnections(traceConnections);
        }

        if (traceConnections.isEmpty()) {
            if (null == mode) {
                mode = RunningModeType.CLIENT;
            }
            switch (mode) {
                case CLIENT:
                    traceConnections.add(defaultOutCon);
                    break;
                case SERVER:
                    traceConnections.add(defaultInCon);
                    break;
                case MITM:
                    traceConnections.add(defaultInCon);
                    traceConnections.add(defaultOutCon);
                    break;
                default:
                    throw new ConfigurationException("No connections defined in workflow trace and "
                            + "default configuration for this running mode (" + mode + ") is not "
                            + "supported. Please define some connections in the workflow trace.\n");
            }
        }

        // If a MITM trace only holds one explicit definition of a connection,
        // add the missing connection from config.
        if (traceConnections.size() == 1 && mode == RunningModeType.MITM) {
            if (traceConnections.get(0).getLocalConnectionEndType() == ConnectionEndType.CLIENT) {
                traceConnections.add(defaultInCon);
            } else {
                traceConnections.add(defaultOutCon);
            }
        }

        for (AliasedConnection traceCon : traceConnections) {
            ConnectionEndType localConEndType = traceCon.getLocalConnectionEndType();
            if (null == localConEndType) {
                throw new ConfigurationException("WorkflowTrace defines a connection with an"
                        + "empty localConnectionEndType. Don't know how to handle this!");
            } else {
                switch (traceCon.getLocalConnectionEndType()) {
                    case CLIENT:
                        traceCon.normalize(defaultOutCon);
                        break;
                    case SERVER:
                        traceCon.normalize(defaultInCon);
                        break;
                    default:
                        throw new ConfigurationException("WorkflowTrace defines a connection with an"
                                + "unknown localConnectionEndType (" + localConEndType + "). Don't know "
                                + "how to handle this!");
                }
            }
        }

        boolean isSingleConnectionWorkflow = true;
        TlsAction customDefaults = new GeneralAction(trace.getConnections().get(0).getAlias());
        if (trace.getConnections().size() > 1) {
            isSingleConnectionWorkflow = false;
        }

        for (TlsAction action : trace.getTlsActions()) {
            if (isSingleConnectionWorkflow) {
                action.normalize(customDefaults);
            } else {
                action.normalize();
            }
            action.setSingleConnectionWorkflow(isSingleConnectionWorkflow);
        }

        assertNormalizedWorkflowTrace(trace);
    }

    public Boolean isNormalized(WorkflowTrace trace) {
        try {
            assertNormalizedWorkflowTrace(trace);
        } catch (ConfigurationException e) {
            return false;
        }
        return true;
    }

    /**
     * Assert that a workflow trace is "well defined". A well defined workflow
     * trace contains one or more Connections and zero or more TlsActions which
     * refer to defined Connections only (i.e. the alias must match a known
     * connection alias).
     *
     * TODO: There could be a AliasedConnection.assertProperlyPrepared() method
     * that we can call here. This would be a "self test" of the Connection
     * object to check that all values are set and in expected range.
     *
     * @param trace
     *            The WorkflowTrace to check
     */
    public void assertNormalizedWorkflowTrace(WorkflowTrace trace) {
        List<AliasedConnection> connections = trace.getConnections();
        if ((connections == null) || (connections.isEmpty())) {
            throw new ConfigurationException("Workflow trace not well defined. "
                    + "Trace does not define any connections.");
        }

        List<String> knownAliases = new ArrayList<>();
        for (AliasedConnection con : connections) {
            String conAlias = con.getAlias();
            if ((conAlias == null) || (conAlias.isEmpty())) {
                throw new ConfigurationException("Workflow trace not well defined. "
                        + "Trace contains connections with empty alias");
            }
            if (knownAliases.contains(conAlias)) {
                throw new ConfigurationException("Workflow trace not well defined. "
                        + "Trace contains connections with the same alias");
            }
            knownAliases.add(conAlias);
        }

        for (TlsAction action : trace.getTlsActions()) {
            try {
                action.assertAliasesSetProperly();
            } catch (ConfigurationException e) {
                throw new ConfigurationException("Workflow trace not well defined. " + e.getLocalizedMessage());
            }

            if (!knownAliases.containsAll(action.getAllAliases())) {
                throw new ConfigurationException("Workflow trace not well defined. "
                        + "Trace has action with reference to unknown connection alias, action: "
                        + action.toCompactString() + ", known aliases: " + knownAliases);
            }
        }
    }
}
