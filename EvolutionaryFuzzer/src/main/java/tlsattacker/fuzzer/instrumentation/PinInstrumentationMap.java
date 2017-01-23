/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.instrumentation;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import tlsattacker.fuzzer.result.MergeResult;

/**
 * This class represents the results of an executed Application instrumented by
 * the PIN Agent
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class PinInstrumentationMap extends InstrumentationMap {

    /**
     * The set of already seen Codeblocks
     */
    private Set<Long> codeblockSet = null;

    /**
     * A map of already seen Edges, implemented as a Map for performance reasons
     */
    private Map<Branch, Branch> branchMap = null;

    public PinInstrumentationMap(Set<Long> codeblockSet, Map<Branch, Branch> branchMap) {
        this.codeblockSet = codeblockSet;
        this.branchMap = branchMap;
    }

    /**
     * Default Constructor
     */
    public PinInstrumentationMap() {
        codeblockSet = new HashSet<>();
        branchMap = new HashMap<>();

    }

    @Override
    public Set<Long> getCodeblocks() {
        return Collections.unmodifiableSet(codeblockSet);
    }

    @Override
    public Set<Branch> getBranches() {
        return Collections.unmodifiableSet(branchMap.keySet());
    }

    @Override
    public boolean didHitNew(InstrumentationMap instrumentationMap) {
        for (Long codeblock : instrumentationMap.getCodeblocks()) {
            if (!codeblockSet.contains(codeblock)) {
                return true;
            }
        }
        for (Branch branch : instrumentationMap.getBranches()) {
            if (!branchMap.containsKey(branch)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public MergeResult merge(InstrumentationMap instrumentationMap) {
        int newCodeblocks = 0;
        int hitCodeblocks = instrumentationMap.getCodeblocks().size();
        int newBranches = 0;
        for (Long v : instrumentationMap.getCodeblocks()) {
            if (codeblockSet.add(v)) {
                newCodeblocks++;
            }

        }
        for (Branch branch : instrumentationMap.getBranches()) {
            if (branchMap.containsValue(branch)) {
                Branch tempBranch = branchMap.get(branch);
                tempBranch.addCounter(branch.getCounter());
            } else {
                branchMap.put(branch, branch);
                newBranches++;
            }
        }
        return new MergeResult(newCodeblocks, newBranches, hitCodeblocks);
    }

}
