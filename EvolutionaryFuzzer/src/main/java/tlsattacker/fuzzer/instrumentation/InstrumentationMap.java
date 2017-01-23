/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.instrumentation;

import java.io.Serializable;
import java.util.List;
import java.util.Set;
import tlsattacker.fuzzer.result.MergeResult;

/**
 * An Abstract representation of the results of an instrumented execution
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class InstrumentationMap implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Returns a list of the hit Codeblocks
     * 
     * @return
     */
    public abstract Set<Long> getCodeblocks();

    /**
     * Returns a list of the hit Branches
     * 
     * @return
     */
    public abstract Set<Branch> getBranches();

    /**
     * Returns true if this InstrumentationMap discovered new Branches or
     * Codeblocks, returns false otherwise
     * 
     * @param instrumentationMap
     *            InstrumentationMap with which to compare too.
     * @return
     */
    public abstract boolean didHitNew(InstrumentationMap instrumentationMap);

    /**
     * Merges the Results from a different InstrumentationMap into this one to
     * get a combines InstrumentationMap. The results of this Merge are returned
     * in a MergeResult object.
     * 
     * @param instrumentationMap
     * @return
     */
    public abstract MergeResult merge(InstrumentationMap instrumentationMap);

}
