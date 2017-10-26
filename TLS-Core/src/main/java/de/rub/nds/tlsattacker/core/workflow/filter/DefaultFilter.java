/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.filter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.socket.AliasedConnection;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceNormalizer;
import de.rub.nds.tlsattacker.core.workflow.action.GeneralAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Internal default filter that strips unnecessary default values.
 * 
 * This filter currently works on a normalized workflow trace only. It is the
 * default filter used before workflow trace serialization.
 */
public class DefaultFilter extends Filter {

    protected static final Logger LOGGER = LogManager.getLogger(DefaultFilter.class);

    public DefaultFilter(Config config) {
        super(config);
    }

    @Override
    public WorkflowTrace filteredCopy(WorkflowTrace trace, Config config) {
        return filteredCopy(trace, config, config.getDefaulRunningMode());
    }

    public WorkflowTrace filteredCopy(WorkflowTrace trace, Config config, RunningModeType mode) {
        WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
        normalizer.assertNormalizedWorkflowTrace(trace);

        WorkflowTrace filteredTrace = WorkflowTrace.copy(trace);

        List<AliasedConnection> traceConnections = filteredTrace.getConnections();
        List<AliasedConnection> strippedTraceConnections = new ArrayList<>();
        AliasedConnection defaultInCon = config.getDefaultServerConnection();
        AliasedConnection defaultOutCon = config.getDefaultClientConnection();

        // Strip defaults of the connections
        AliasedConnection lastDefaultCon = null;
        for (AliasedConnection traceCon : traceConnections) {
            ConnectionEndType localConEndType = traceCon.getLocalConnectionEndType();
            if (null == localConEndType) {
                throw new ConfigurationException("WorkflowTrace defines a connection with an"
                        + "empty localConnectionEndType. Don't know how to handle this!");
            } else {
                switch (traceCon.getLocalConnectionEndType()) {
                    case CLIENT:
                        lastDefaultCon = defaultOutCon;
                        break;
                    case SERVER:
                        lastDefaultCon = defaultInCon;
                        break;
                    default:
                        throw new ConfigurationException("WorkflowTrace defines a connection with an"
                                + "unknown localConnectionEndType (" + localConEndType + "). Don't know "
                                + "how to handle this!");
                }
                traceCon.filter(lastDefaultCon);
            }
        }

        // If we have one or two connections that match the default config
        // connections exactly, do not add them to output.
        if (traceConnections.size() <= 2) {
            for (AliasedConnection traceCon : traceConnections) {
                if (traceCon.equals(defaultInCon)) {
                    lastDefaultCon = defaultInCon;
                } else if (traceCon.equals(defaultOutCon)) {
                    lastDefaultCon = defaultOutCon;
                } else {
                    strippedTraceConnections.add(traceCon);
                }
            }
        }

        if (filteredTrace.getTlsActions() != null) {
            TlsAction defaultAction = new GeneralAction(lastDefaultCon.getAlias());
            for (TlsAction action : filteredTrace.getTlsActions()) {
                action.filter(defaultAction);
            }
        }

        filteredTrace.setConnections(strippedTraceConnections);
        return filteredTrace;
    }

}
