/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package WorkFlowType;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.jgrapht.DirectedGraph;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DirectedMultigraph;
import org.jgrapht.graph.ListenableDirectedGraph;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowGraphBuilder {
    public static DirectedMultigraph<Integer, MessageFlow> generateWorkflowGraph(Set<WorkflowTraceType> typeList) {
	DirectedMultigraph<Integer, MessageFlow> graph = new DirectedMultigraph<>(MessageFlow.class);
	int vertexIndex = 0;
	int uniquer = 0;
	graph.addVertex(0);

	for (WorkflowTraceType type : typeList) {
	    int current = 0;
	    List<MessageFlow> flows = type.getFlows();
	    for (MessageFlow flow : flows) {

		MessageFlow temp = returnOutGoingFlow(graph, flow, current);
		if (temp == null) {
		    vertexIndex++;
		    uniquer++;
		    flow.setUniquer(uniquer);
		    graph.addVertex(vertexIndex);
		    boolean b = graph.addEdge(current, vertexIndex, flow);
		    current = vertexIndex;
		} else {
		    current = graph.getEdgeTarget(temp);
		}
	    }
	}

	return graph;
    }

    public static MessageFlow returnOutGoingFlow(DirectedMultigraph<Integer, MessageFlow> graph, MessageFlow flow,
	    Integer current) {
	for (MessageFlow f : graph.outgoingEdgesOf(current)) {
	    if (f.getIssuer() == flow.getIssuer() && f.getMessage() == flow.getMessage()) {
		return f;
	    }
	}
	return null;
    }
}
