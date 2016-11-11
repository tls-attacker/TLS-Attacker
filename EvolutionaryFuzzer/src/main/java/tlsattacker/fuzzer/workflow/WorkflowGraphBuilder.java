/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.workflow;

import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import org.jgrapht.graph.DirectedMultigraph;

/**
 * A helper class which helps in the generation of visualizable workflow data
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowGraphBuilder {

    /**
     * 
     * @param typeList
     * @return
     */
    public static String generateDOTGraph(Set<WorkflowTraceType> typeList) {
        String result = "digraph output{\n";
        int vertexIndex = 0;
        int uniquer = 0;

        DirectedMultigraph<Integer, MessageFlow> graph = generateWorkflowGraph(typeList);
        for (Integer i : graph.vertexSet()) {
            result += "" + i + " [label=\"" + i + "\"];\n";
        }
        for (MessageFlow flow : graph.edgeSet()) {
            result += "" + graph.getEdgeSource(flow) + " -> " + graph.getEdgeTarget(flow) + " [label=\""
                    + flow.toString() + "\"];\n";
        }
        result += "}";

        return result;
    }

    /**
     * 
     * @param typeList
     * @return
     */
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

    /**
     * 
     * @param graph
     * @param flow
     * @param current
     * @return
     */
    public static MessageFlow returnOutGoingFlow(DirectedMultigraph<Integer, MessageFlow> graph, MessageFlow flow,
            Integer current) {
        for (MessageFlow f : graph.outgoingEdgesOf(current)) {
            if (f.getIssuer() == flow.getIssuer() && f.getMessage() == flow.getMessage()) {
                return f;
            }
        }
        return null;
    }

    /**
     *
     */
    private WorkflowGraphBuilder() {
    }

    private static final Logger LOG = Logger.getLogger(WorkflowGraphBuilder.class.getName());
}
