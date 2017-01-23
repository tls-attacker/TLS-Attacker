/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.instrumentation;

import java.util.HashSet;
import java.util.Set;
import tlsattacker.fuzzer.result.MergeResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class EmptyInstrumentationMap extends InstrumentationMap {

    @Override
    public Set<Long> getCodeblocks() {
        return new HashSet<>();
    }

    @Override
    public Set<Branch> getBranches() {
        return new HashSet<>();
    }

    @Override
    public boolean didHitNew(InstrumentationMap instrumentationMap) {
        return false;
    }

    @Override
    public MergeResult merge(InstrumentationMap instrumentationMap) {
        return new MergeResult(0, 0, 0);
    }

}
