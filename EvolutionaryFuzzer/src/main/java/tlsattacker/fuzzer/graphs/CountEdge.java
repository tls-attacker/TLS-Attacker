/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.graphs;

import java.util.logging.Logger;

/**
 * An implementation of JGrapgTs default edge which carries a counter.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class CountEdge extends org.jgrapht.graph.DefaultEdge {

    /**
     * SerialVersion Unique Identifier for version compatibility
     */
    private static final long serialVersionUID = 1L;

    /**
     * Branch Counter
     */
    private int count = 1;

    /**
     * Default Constructor
     */
    public CountEdge() {
    }

    /**
     * Increments the counter
     */
    public void increment() {
        count++;
    }

    public void add(int count) {
        this.count += count;
    }

    /**
     * Returns the Count value of the Edge
     * 
     * @return Count value of the Edge
     */
    public int getCount() {
        return count;
    }

    @Override
    public Object clone() {
        return super.clone(); // To change body of generated methods, choose
        // Tools | Templates.
    }

    private static final Logger LOG = Logger.getLogger(CountEdge.class.getName());
}
