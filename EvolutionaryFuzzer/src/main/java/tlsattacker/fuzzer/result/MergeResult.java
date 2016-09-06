/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.result;

import java.util.logging.Logger;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MergeResult {
    private static final Logger LOG = Logger.getLogger(MergeResult.class.getName());

    private int newVertices = 0;
    private int newBranches = 0;
    private int hitVertices = 0;

    /**
     * 
     * @param newVertices
     * @param newBranches
     * @param hitVertices
     */
    public MergeResult(int newVertices, int newBranches, int hitVertices) {
	this.hitVertices = hitVertices;
	this.newBranches = newBranches;
	this.newVertices = newVertices;

    }

    /**
     * 
     * @return
     */
    public int getNewVertices() {
	return newVertices;
    }

    /**
     * 
     * @return
     */
    public int getNewBranches() {
	return newBranches;
    }

    /**
     * 
     * @return
     */
    public int getHitVertices() {
	return hitVertices;
    }

    /**
     * 
     * @return
     */
    @Override
    public String toString() {
	return "New Vertices:" + newVertices + "  New Branches:" + newBranches + "  Hit Verticies:" + hitVertices;
    }
}
