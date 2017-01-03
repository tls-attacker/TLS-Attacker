/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.result;

/**
 * A class which represents the outcome of a BranchTrace merge operation. It
 * contains statistics about the different new found vertices, branches, and hit
 * vertices at all.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class MergeResult {

    /**
     * Number of newly discovered Code blocks
     */
    private int newVertices = 0;

    /**
     * Number of newly discovered Code branches
     */
    private int newBranches = 0;

    /**
     * Number of hit Vertices
     */
    private int hitVertices = 0;

    public MergeResult(int newVertices, int newBranches, int hitVertices) {
        this.hitVertices = hitVertices;
        this.newBranches = newBranches;
        this.newVertices = newVertices;

    }

    public int getNewVertices() {
        return newVertices;
    }

    public int getNewBranches() {
        return newBranches;
    }

    public int getHitVertices() {
        return hitVertices;
    }

    @Override
    public String toString() {
        return "New Vertices:" + newVertices + "  New Branches:" + newBranches + "  Hit Verticies:" + hitVertices;
    }

}
