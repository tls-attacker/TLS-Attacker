/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.graphs;

import tlsattacker.fuzzer.result.MergeResult;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * This Class organizes the Controlflow of previous executed FuzzVectors. The
 * Fuzzer stores the Different Branches it hits by a List of ProbeIDs. Each
 * ProbeID represents a Single Instrumentation Point in the Code. A Branchtrace
 * can be extended by Merging it with Files containing a list of consecutive
 * ProbeIds. The whole Controlflow is stored in a Directed Graph, where the
 * Vertices of the Graph represent a single ProbeID and the Branches of the
 * Graph represent transitions between different ProbeIDs. Each Transitions
 * stores a counter how often the Fuzzer detected this Transition. To calculate
 * how often a ProbeID was encountered one would have to calculate the Sum of
 * all incoming Branches of a ProbeID.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class BranchTrace implements Serializable {

    private static final Logger LOG = Logger.getLogger(BranchTrace.class.getName());

    // A Map which maps ProbeIDs to Vertices to better Acess the Vertices in the
    // Graph
    private Set<Long> verticesSet = null;
    private Map<Edge, Edge> edgeMap = null;

    public Set<Long> getVerticesSet() {
	return verticesSet;
    }

    public Map<Edge, Edge> getEdgeMap() {
	return edgeMap;
    }

    public BranchTrace(Set<Long> verticesSet, Map<Edge, Edge> edgeMap) {
	this.verticesSet = verticesSet;
	this.edgeMap = edgeMap;
    }

    /**
     * Default Constructor
     */
    public BranchTrace() {
	verticesSet = new HashSet<>();
	edgeMap = new HashMap<>();

    }

    public MergeResult merge(BranchTrace trace) {
	int newVertices = 0;
	int hitVertices = trace.verticesSet.size();
	int newEdges = 0;
	for (Long v : trace.verticesSet) {
	    if (verticesSet.add(v)) {
		newVertices++;
	    }

	}
	for (Edge edge : trace.edgeMap.values()) {
	    if (edgeMap.containsValue(edge)) {
		Edge e = edgeMap.get(edge);
		e.addCounter(edge.getCounter());
	    } else {
		edgeMap.put(edge, edge);
		newEdges++;
	    }
	}
	return new MergeResult(newVertices, newEdges, hitVertices);
    }

    public int getVerticesCount() {
	return verticesSet.size();
    }

    public int getBranchCount() {
	return edgeMap.size();
    }

}
