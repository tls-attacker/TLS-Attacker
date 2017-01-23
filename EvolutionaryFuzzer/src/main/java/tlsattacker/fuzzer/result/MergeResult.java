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
     * Number of newly discovered Codeblocks
     */
    private int newCodeblocks = 0;

    /**
     * Number of newly discovered Code branches
     */
    private int newBranches = 0;

    /**
     * Number of hit Codeblocks
     */
    private int hitCodeblocks = 0;

    public MergeResult(int newVertices, int newBranches, int hitVertices) {
        this.hitCodeblocks = hitVertices;
        this.newBranches = newBranches;
        this.newCodeblocks = newVertices;

    }

    public int getNewCodeblocks() {
        return newCodeblocks;
    }

    public int getNewBranches() {
        return newBranches;
    }

    public int getHitCodeblocks() {
        return hitCodeblocks;
    }

    @Override
    public String toString() {
        return "New Codeblocks:" + newCodeblocks + "  New Branches:" + newBranches + "  Hit Codeblocks:"
                + hitCodeblocks;
    }

}
