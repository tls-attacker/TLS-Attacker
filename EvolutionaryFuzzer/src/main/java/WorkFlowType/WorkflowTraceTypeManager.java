/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package WorkFlowType;

import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowTraceTypeManager {

    /**
     * Generates a Set of WorkFlowTraceTypes, each WorkFlowTraceType represents
     * a Category of Workflowtraces which reached a new Branch in the
     * Implementation at some Point.
     * 
     * @param traces
     * @return
     */
    public static Set<WorkFlowTraceType> generateTypeList(List<WorkflowTrace> traces) {
	Set<WorkFlowTraceType> set = new HashSet<>();
	for (WorkflowTrace trace : traces) {
	    WorkFlowTraceType type = generateWorkflowTraceType(trace);
	    set.add(type);
	}
	return set;
    }

    /**
     * Generates a Set of WorkFlowTraceTypes, each WorkFlowTraceType represents
     * a Category of Workflowtraces which reached a new Branch in the
     * Implementation at some Point. WorkflowTraces that didn't end with a
     * Message from the Server are scrapped from the Client Messages to that
     * Point. The List then represents all WorkflowTraceTypes which bring the
     * Server in different States.
     * 
     * @param traces
     * @return
     */
    public static Set<WorkFlowTraceType> generateCleanTypeList(List<WorkflowTrace> traces) {
	Set<WorkFlowTraceType> set = new HashSet<>();
	for (WorkflowTrace trace : traces) {
	    WorkFlowTraceType type = generateWorkflowTraceType(trace);
	    type.clean();
	    set.add(type);
	}
	return set;
    }

    /**
     * Generates a WorkflowTraceType for a WorkflowTrace.
     * 
     * @param trace
     *            Trace for which the WorkflowTraceType should be generated
     * @return
     */
    public static WorkFlowTraceType generateWorkflowTraceType(WorkflowTrace trace) {
	WorkFlowTraceType type = new WorkFlowTraceType();
	for (ProtocolMessage m : trace.getProtocolMessages()) {
	    MessageFlow flow = new MessageFlow(m.getClass(), m.getMessageIssuer());
	    type.addMessageFlow(flow);
	}
	return type;
    }
}
