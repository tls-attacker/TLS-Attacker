/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.workflow;

import tlsattacker.fuzzer.testvector.TestVector;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowTraceTypeManager {

    /**
     * Generates a Set of WorkFlowTraceTypes, each WorkflowTraceType represents
     * a Category of Workflowtraces which reached a new Branch in the
     * Implementation at some Point.
     * 
     * @param traces
     * @return
     */
    public static Set<WorkflowTraceType> generateTypeList(List<TestVector> vectors, ConnectionEnd connectionEnd) {
	Set<WorkflowTraceType> set = new HashSet<>();
	for (TestVector vector : vectors) {
	    WorkflowTraceType type = generateWorkflowTraceType(vector.getTrace(), connectionEnd);
	    set.add(type);
	}
	return set;
    }
    public static Set<WorkflowTraceType> generateResponseTypeList(List<TestVector> vectors, ConnectionEnd connectionEnd) {
	Set<WorkflowTraceType> set = new HashSet<>();
	for (TestVector vector : vectors) {
	    WorkflowTraceType type = generateWorkflowTraceTypeResponse(vector.getTrace(), connectionEnd);
	    set.add(type);
	}
	return set;
    }
    /**
     * Generates a Set of WorkFlowTraceTypes, each WorkflowTraceType represents
     * a Category of Workflowtraces which reached a new Branch in the
     * Implementation at some Point. WorkflowTraces that didn't end with a
     * Message from the Server are scrapped from the Client Messages to that
     * Point. The List then represents all WorkflowTraceTypes which bring the
     * Server in different States.
     * 
     * @param traces
     * @return
     */
    public static Set<WorkflowTraceType> generateCleanTypeList(List<TestVector> vectors, ConnectionEnd myConnectionEnd) {
	Set<WorkflowTraceType> set = new HashSet<>();
	for (TestVector vector : vectors) {
	    WorkflowTraceType type = generateWorkflowTraceType(vector.getTrace(), myConnectionEnd);
	    type.clean();
	    set.add(type);
	}
	return set;
    }
     public static Set<WorkflowTraceType> generateCleanResponseTypeList(List<TestVector> vectors, ConnectionEnd myConnectionEnd) {
	Set<WorkflowTraceType> set = new HashSet<>();
	for (TestVector vector : vectors) {
	    WorkflowTraceType type = generateWorkflowTraceTypeResponse(vector.getTrace(), myConnectionEnd);
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
    public static WorkflowTraceType generateWorkflowTraceTypeResponse(WorkflowTrace trace, ConnectionEnd myConnectionEnd) {
	WorkflowTraceType type = new WorkflowTraceType();
	for (TLSAction action : trace.getTLSActions()) {
	    if (action.isExecuted() && action instanceof MessageAction) {
		MessageAction msgAction = (MessageAction) action;
		if (msgAction instanceof ReceiveAction) {
		    for (ProtocolMessage message : msgAction.getActualMessages()) {
			MessageFlow flow = new MessageFlow(message.getClass(), myConnectionEnd);
			type.addMessageFlow(flow);
		    }
                }
	    }
	}
	return type;
    }
    /**
     * Generates a WorkflowTraceType for a WorkflowTrace.
     * 
     * @param trace
     *            Trace for which the WorkflowTraceType should be generated
     * @return
     */
    public static WorkflowTraceType generateWorkflowTraceType(WorkflowTrace trace, ConnectionEnd myConnectionEnd) {
	WorkflowTraceType type = new WorkflowTraceType();
	for (TLSAction action : trace.getTLSActions()) {
	    if (action.isExecuted() && action instanceof MessageAction) {
		MessageAction msgAction = (MessageAction) action;
		if (msgAction instanceof SendAction) {
		    for (ProtocolMessage message : msgAction.getActualMessages()) {
			MessageFlow flow = new MessageFlow(message.getClass(), myConnectionEnd);
			type.addMessageFlow(flow);
		    }
		} else {
		    for (ProtocolMessage message : msgAction.getActualMessages()) {
			MessageFlow flow = new MessageFlow(message.getClass(),
				myConnectionEnd == ConnectionEnd.CLIENT ? ConnectionEnd.SERVER : ConnectionEnd.CLIENT);
			type.addMessageFlow(flow);
		    }

		}
	    }
	}
	return type;
    }
}
