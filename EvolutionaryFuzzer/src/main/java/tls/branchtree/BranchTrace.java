/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.branchtree;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Logger;
import org.jgrapht.DirectedGraph;
import org.jgrapht.graph.DefaultDirectedGraph;

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
public class BranchTrace {
    private static final Logger LOG = Logger.getLogger(BranchTrace.class.getName());

    // A Map which maps ProbeIDs to Vertices to better Acess the Vertices in the
    // Graph
    private HashMap<Long, ProbeVertex> map = null;
    // Graph which contains all the relevant Data
    private final DirectedGraph<ProbeVertex, CountEdge> graph;

    /**
     * Default Constructor
     */
    public BranchTrace() {
	map = new HashMap<>();
	graph = new DefaultDirectedGraph<>(CountEdge.class);
    }

    /**
     * Returns the DirectedGraph of the Trace
     * 
     * @return Directed Graph of the Trace
     */
    public DirectedGraph<ProbeVertex, CountEdge> getGraph() {
	return graph;
    }

    /**
     * Merges a File with ProbeIDs with the current Graph. The File should
     * contain ProbeIDs of a Binary Execution. The ProbeIDs should be saved as
     * longs in the File, one long per File, where 2 consecutive ProbeIDs mean
     * that there is a Branch from the first ID to the second.
     * 
     * @param f
     *            File which contains the ProbeIDs
     * @return Result Objects, which contains Information about new Findings in
     *         the trace
     * @throws FileNotFoundException
     *             If the File cannot be found
     * @throws IOException
     *             If the File cannot be accessed
     */
    public MergeResult merge(File f) throws FileNotFoundException, IOException {
	if (f == null) {
	    throw new NullPointerException("Cannot merge BranchTrace with a Null File");
	}
	if (!f.exists()) {
	    throw new FileNotFoundException("Cannot merge BranchTrace with not-existant File:" + f.getAbsolutePath());
	}
	int newEdges = 0;
	int newVertices = 0;
	int hitVertices = 0;

	BufferedReader br = new BufferedReader(new FileReader(f));

	long previousNumber = Long.MIN_VALUE;
	String line = null;

	while ((line = br.readLine()) != null) {
	    // Check if the Line can be parsed
	    long parsedNumber;
	    try {

		parsedNumber = Long.parseLong(line, 16);
	    } catch (NumberFormatException e) {
		throw new NumberFormatException("BranchTrace contains unparsable Lines: " + line);
	    }
	    hitVertices++;
	    if (previousNumber == Long.MIN_VALUE) {
		// EntryPoint
		ProbeVertex entryPoint = map.get(0l);
		ProbeVertex vertice = map.get(Long.parseLong(line, 16));
		if (entryPoint == null) {
		    entryPoint = new ProbeVertex(0);
		    map.put(entryPoint.getProbeID(), entryPoint);
		    graph.addVertex(entryPoint);
		    newVertices++;
		}
		if (vertice == null) {
		    vertice = new ProbeVertex(Long.parseLong(line, 16));
		    map.put(parsedNumber, vertice);
		    graph.addVertex(vertice);
		    newVertices++;
		}
		CountEdge edge = graph.getEdge(entryPoint, vertice);
		if (edge == null) {
		    graph.addEdge(entryPoint, vertice);
		    newEdges++;
		} else {
		    edge.increment();
		}

	    } else {
		ProbeVertex from = map.get(previousNumber);
		ProbeVertex to = map.get(parsedNumber);

		if (to == null) {
		    to = new ProbeVertex(parsedNumber);
		    graph.addVertex(to);
		    map.put(parsedNumber, to);
		    newVertices++;
		}
		CountEdge edge = graph.getEdge(from, to);
		if (edge == null) {
		    graph.addEdge(from, to);
		    newEdges++;
		} else {
		    edge.increment();
		}
	    }
	    previousNumber = parsedNumber;
	}

	return new MergeResult(newVertices, newEdges, hitVertices);
    }

    public int getVerticesCount() {
	return map.size();
    }

    public int getBranchCount() {
	return graph.edgeSet().size();
    }

}
