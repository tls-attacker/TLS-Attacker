/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.graphs;

import java.io.Serializable;
import java.util.logging.Logger;

/**
 * An edge class wbich represents an edge from one probe id to another. Carries a counter to count how often it appeared.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class Edge implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = Logger.getLogger(Edge.class.getName());
    private long a;
    private long b;
    private long counter = 0;

    /**
     * Default Constructor
     * 
     * @param a
     * @param b
     */
    public Edge(long a, long b) {
	this.a = a;
	this.b = b;
    }

    public long getA() {
	return a;
    }

    public long getB() {
	return b;
    }

    public long getCounter() {
	return counter;
    }

    public void setCounter(long counter) {
	this.counter = counter;
    }

    public void addCounter(long counter) {
	this.counter += counter;
    }

    @Override
    public int hashCode() {
	int hash = 7;
	hash = 41 * hash + (int) (this.a ^ (this.a >>> 32));
	hash = 41 * hash + (int) (this.b ^ (this.b >>> 32));
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
	if (this.a != other.a) {
	    return false;
	}
	if (this.b != other.b) {
	    return false;
	}
	return true;
    }

}
