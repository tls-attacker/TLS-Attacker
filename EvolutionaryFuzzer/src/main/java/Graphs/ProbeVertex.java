/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Graphs;

import java.util.logging.Logger;

/**
 * This Object Represents a ProbeId in a Vertex in a Graph.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ProbeVertex {

    private static final Logger LOG = Logger.getLogger(ProbeVertex.class.getName());
    // The stored probeID
    private final long probeID;

    /**
     * Default Constructor
     * 
     * @param probeID
     *            ProbeID stored in the Vertex
     */
    public ProbeVertex(long probeID) {
	this.probeID = probeID;
    }

    /**
     * 
     * @return
     */
    @Override
    public int hashCode() {
	return Long.valueOf(probeID).hashCode();
    }

    /**
     * Returns the ProbeID stored in the Vertex
     * 
     * @return ProbeID stored in the Vertex
     */
    public long getProbeID() {
	return probeID;
    }

    /**
     * Two Vertices are Equal if they have the same ProbeID
     * 
     * @param other
     * @return True if both Objects have the same ProbeID, else false
     */
    @Override
    public boolean equals(Object other) {
	if (other.getClass().equals(this.getClass())) {
	    ProbeVertex vertice = (ProbeVertex) other;
	    return vertice.getProbeID() == this.probeID;
	}
	return false;
    }

    /**
     * Returns a String representation of the Object
     * 
     * @return String of the form: CountVertice{probeID=}
     */
    @Override
    public String toString() {
	return "CountVertice{" + "probeID=" + probeID + '}';
    }

}
