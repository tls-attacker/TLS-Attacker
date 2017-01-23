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
 * The AFL Bitmap. Since AFL loses the information about the exactly hit
 * Codeblocks we do not provide this Information here and return null if asked.
 * AFL stores its instrumentation output in a 64kb big bitmap where each byte
 * represents a possibly hit edge. If a byte value is greater than zero, the
 * edge is considered hit. Counters are not reliable and are able to wrap around
 * zero and are therfore considered as a guidance rather than exact information.
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AFLInstrumentationMap extends InstrumentationMap {

    // The AFL Bitmap
    private long[] bitmap;

    public AFLInstrumentationMap(long[] bitmap) {
        this.bitmap = bitmap;
    }

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
        if (!(instrumentationMap instanceof AFLInstrumentationMap)) {
            throw new UnsupportedOperationException("AFL maps can only be compared to other AFL maps");
        }
        AFLInstrumentationMap aflMap = (AFLInstrumentationMap) instrumentationMap;
        assert aflMap.bitmap.length == bitmap.length;
        for (int i = 0; i < bitmap.length; i++) {
            if (bitmap[i] > 0 && aflMap.bitmap[i] == 0) {
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
        if (!(instrumentationMap instanceof AFLInstrumentationMap)) {
            throw new UnsupportedOperationException("AFL maps can only be compared to other AFL maps");
        }
        AFLInstrumentationMap aflMap = (AFLInstrumentationMap) instrumentationMap;
        assert aflMap.bitmap.length == bitmap.length;
        for (int i = 0; i < bitmap.length; i++) {
            if (aflMap.bitmap[i] != 0) {
                if (bitmap[i] == 0) {
                    newCodeblocks++;
                    newBranches++;
                }
                hitCodeblocks++;
            }
            bitmap[i] += aflMap.bitmap[i];
        }
        return new MergeResult(newCodeblocks, newBranches, hitCodeblocks);
    }

}
