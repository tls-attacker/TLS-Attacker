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
     * The identifier of this Codeblock
     */
    private long probeID;

    /**
     * The type of this codeblock
     */
    private Blocktype type;

    /**
     * A label for this Codeblock
     */
    private String label;

    public BranchVertex(long probeID, Blocktype type) {
        this.probeID = probeID;
        this.type = type;
        label = "";
    }

    public BranchVertex(long probeID, Blocktype type, String label) {
        this.probeID = probeID;
        this.type = type;
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public long getProbeID() {
        return probeID;
    }

    public Blocktype getType() {
        return type;
    }

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
    public int hashCode() {
        int hash = 7;
        hash = 83 * hash + (int) (this.probeID ^ (this.probeID >>> 32));
        hash = 83 * hash + Objects.hashCode(this.type);
        hash = 83 * hash + Objects.hashCode(this.label);
        return hash;
    }

    /**
     * Returns a Human readable representation of this Object
     * 
     * @return A Human readable representation of this Object
     */
    @Override
    public String toString() {
        return "CountVertice{" + "probeID=" + probeID + '}';
    }

    private static final Logger LOG = Logger.getLogger(BranchVertex.class.getName());
}
