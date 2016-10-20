/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.graphs;

import java.util.Objects;
import java.util.logging.Logger;

/**
 * A class which represents a node from a branch.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class BranchVertex {

    /**
     *
     */
    private static final Logger LOG = Logger.getLogger(BranchVertex.class.getName());

    /**
     *
     */
    private long probeID;

    /**
     *
     */
    private Blocktype type;

    /**
     *
     */
    private String label;

    /**
     * 
     * @param probeID
     * @param type
     */
    public BranchVertex(long probeID, Blocktype type) {
	this.probeID = probeID;
	this.type = type;
	label = "";
    }

    /**
     * 
     * @param probeID
     * @param type
     * @param label
     */
    public BranchVertex(long probeID, Blocktype type, String label) {
	this.probeID = probeID;
	this.type = type;
	this.label = label;
    }

    /**
     * 
     * @return
     */
    public String getLabel() {
	return label;
    }

    /**
     * 
     * @return
     */
    public long getProbeID() {
	return probeID;
    }

    /**
     * 
     * @return
     */
    public Blocktype getType() {
	return type;
    }

    /**
     * 
     * @param other
     * @return
     */
    @Override
    public boolean equals(Object other) {
	if (other.getClass().equals(this.getClass())) {
	    BranchVertex vertice = (BranchVertex) other;
	    return vertice.getProbeID() == this.probeID && vertice.label.equals(this.label)
		    && vertice.getType().equals(this.type);
	}
	return false;
    }

    @Override
    public int hashCode()
    {
        int hash = 7;
        hash = 83 * hash + (int) (this.probeID ^ (this.probeID >>> 32));
        hash = 83 * hash + Objects.hashCode(this.type);
        hash = 83 * hash + Objects.hashCode(this.label);
        return hash;
    }

    /**
     * 
     * @return
     */
    @Override
    public String toString() {
	return "CountVertice{" + "probeID=" + probeID + '}';
    }
}
