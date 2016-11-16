/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.graphs;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import tlsattacker.fuzzer.result.MergeResult;

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
    /**
     * The set of already seen Codeblocks
     */
    private Set<Long> verticesSet = null;

    /**
     * A map of already seen Edges, implemented as a Map for performance reasons
     */
    private Map<Edge, Edge> edgeMap = null;

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

    public Set<Long> getVerticesSet() {
        return Collections.unmodifiableSet(verticesSet);
    }

    public Map<Edge, Edge> getEdgeMap() {
        return Collections.unmodifiableMap(edgeMap);
    }

    /**
     * Merges another BranchTrace into this one and returns a result object
     * which shows how many new codeblocks or branches were detected. This
     * BranchTrace contains all branches and codeblocks of both BranchTraces
     * after execution.
     * 
     * @param trace
     *            The BranchTrace to merge with
     * @return A MergeResult which keeps track of merge statistics
     */
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

    private static final Logger LOG = Logger.getLogger(BranchTrace.class.getName());
}
