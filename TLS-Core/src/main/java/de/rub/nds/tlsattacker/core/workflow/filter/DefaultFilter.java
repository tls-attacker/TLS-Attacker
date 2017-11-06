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
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
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
 * This filter works on a normalized workflow trace only. It is the default
 * filter that is normally used before workflow trace serialization.
 */
public class DefaultFilter extends Filter {

    protected static final Logger LOGGER = LogManager.getLogger(DefaultFilter.class);

    public DefaultFilter(Config config) {
        super(config);
    }

    /**
     * Apply filter to trace.
     * 
     * @param trace
     *            The workflow trace that should be filtered.
     */
    @Override
    public void applyFilter(WorkflowTrace trace) {
        WorkflowTraceNormalizer normalizer = new WorkflowTraceNormalizer();
        normalizer.assertNormalizedWorkflowTrace(trace);

        List<AliasedConnection> traceConnections = trace.getConnections();
        List<AliasedConnection> strippedTraceConnections = new ArrayList<>();
        InboundConnection defaultInCon = config.getDefaultServerConnection().getCopy();
        OutboundConnection defaultOutCon = config.getDefaultClientConnection().getCopy();

        // Strip defaults of the connections
        AliasedConnection lastProcessedCon = null;
        for (AliasedConnection traceCon : traceConnections) {
            ConnectionEndType localConEndType = traceCon.getLocalConnectionEndType();
            if (null == localConEndType) {
                throw new ConfigurationException("WorkflowTrace defines a connection with an"
                        + "empty localConnectionEndType. Don't know how to handle this!");
            } else {
                lastProcessedCon = traceCon.getCopy();
                switch (traceCon.getLocalConnectionEndType()) {
                    case CLIENT:
                        traceCon.filter(defaultOutCon);
                        break;
                    case SERVER:
                        traceCon.filter(defaultInCon);
                        break;
                    default:
                        throw new ConfigurationException("WorkflowTrace defines a connection with an"
                                + "unknown localConnectionEndType (" + localConEndType + "). Don't know "
                                + "how to handle this!");
                }

            }
        }

        // Remove unnecessary action connection aliases
        TlsAction defaultAction = new GeneralAction(lastProcessedCon.getAlias());
        if (trace.getTlsActions() != null) {
            for (TlsAction action : trace.getTlsActions()) {
                action.filter(defaultAction);
            }
        }

        trace.setConnections(strippedTraceConnections);
    }

    /**
     * Restore workflow trace values that were explicitly set by the user.
     * <p>
     * Currently restores only workflow trace connections set by the user.
     * 
     * @param trace
     *            the trace to which the postFilter should be applied
     * @param reference
     *            the reference trace holding the original user defined values
     * 
     */
    @Override
    public void postFilter(WorkflowTrace trace, WorkflowTrace reference) {
        trace.setConnections(reference.getConnections());
    }

    @Override
    public FilterType getFilterType() {
        return FilterType.DEFAULT;
    }

}
