/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1.oracles;

import de.rub.nds.tlsattacker.attacks.pkcs1.OracleException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Oracle template for Bleichenbacher/Manger attack.
 *
 * @version 0.1 Jun 12, 2012
 */
public abstract class Pkcs1Oracle {

    /**
     * logger
     */
    private static final Logger LOGGER = LogManager.getLogger();

    /*
     * number of queries issued to oracle
     */
    /**
     *
     */
    protected long numberOfQueries;
    /*
     * block size of the encryption algorithm
     */

    /**
     *
     */
    protected int blockSize;
    /*
     * public key of the oracle
     */

    /**
     *
     */
    protected RSAPublicKey publicKey;
    /*
     * a boolean value indicating if the oracle is a plaintext oracle (oracle
     * used for testing purposes) or a real oracle needing to decrypt each
     * ciphertext.
     */

    /**
     *
     */
    protected boolean isPlaintextOracle = false;
    /**
     * oracle type according to the Crypto'12 paper
     */
    protected OracleType oracleType = null;

    /**
     * Gets the blocksize of the encryption algorithm.
     *
     * @return Blocksize
     */
    public int getBlockSize() {
        return this.blockSize;
    }

    /**
     * Gets the total number of queries performed by this oracle.
     *
     * @return Number of queries
     */
    public long getNumberOfQueries() {
        return this.numberOfQueries;
    }

    /**
     * Gets the public key of this oracle.
     *
     * @return Public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Checks for PKCS conformity - 00 02 padding 00 pms
     *
     * @param msg
     *            Encrypted message to check for conformity
     * @return True if PKCS conforming, else false
     */
    public abstract boolean checkPKCSConformity(final byte[] msg) throws OracleException;

    /**
     * Returns true if the oracle is a plaintext oracle (does not decrypt the
     * data received)
     *
     * @return isPlaintextOracle
     */
    public boolean isPlaintextOracle() {
        return isPlaintextOracle;
    }

    /**
     * Returns the oracle type
     *
     * @return
     */
    public OracleType getOracleType() {
        return oracleType;
    }

    /**
     *
     */
    public void resetNumberOfQueries() {
        this.numberOfQueries = 0;
    }

    /**
     * Oracle types defined in the Crypto'12 paper + specific oracles found
     * during our research
     *
     * TTT checks only 0x00 0x02 ...
     *
     * FFF checks 0x00 0x02 on the beginning, the first 8 bytes cannot include
     * 0x00 and the 0x00 byte has to be set on a correct position
     *
     * XMLENC checks if the key has a correct length (16, 24, or 32 bytes)
     *
     * BigIP checks only the second byte 0x02 (the first 0x00 byte is not
     * checked at all)
     *
     * MANGER_0x00 checks only the first byte is equal to 0x00
     */
    public enum OracleType {

        /**
         *
         */
        TTT,
        /**
         *
         */
        TFT,
        /**
         *
         */
        FTT,
        /**
         *
         */
        FFT,
        /**
         *
         */
        FFF,
        /**
         *
         */
        JSSE,
        /**
         *
         */
        XMLENC,
        /**
         *
         */
        BigIP,
        /**
         *
         */
        MANGER_0x00
    }
}
