/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.graphs;

import java.io.Serializable;

/**
 * An edge class which represents an edge from one probe id to another. Carries
 * a counter to count how often it appeared.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class Edge implements Serializable {

    /**
     * SerialVersion Unique Identifier for version compatibility
     */
    private static final long serialVersionUID = 1L;

    /**
     * Edge Source probeID
     */
    private final long source;

    /**
     * Edge Destination probeID
     */
    private final long Destination;

    /**
     * A counter which counts how often this edge has been seen
     */
    private long counter = 0;

    public Edge(long source, long destination) {
        this.source = source;
        this.Destination = destination;
    }

    public long getSource() {
        return source;
    }

    public long getDestination() {
        return Destination;
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }

    /**
     * Adds a value to counter
     * 
     * @param counter
     *            Value to increase the counter by
     */
    public void addCounter(long counter) {
        this.counter += counter;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 41 * hash + (int) (this.source ^ (this.source >>> 32));
        hash = 41 * hash + (int) (this.Destination ^ (this.Destination >>> 32));
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Edge other = (Edge) obj;
        if (this.source != other.source) {
            return false;
        }
        return this.Destination == other.Destination;
    }

}
