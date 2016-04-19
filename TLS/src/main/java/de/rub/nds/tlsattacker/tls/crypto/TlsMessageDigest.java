/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.crypto;

import de.rub.nds.tlsattacker.tls.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Computes message digest for two algorithms at once, typically for MD5 and
 * SHA1 for TLS 1.0. At the end it returns MD5(value) || SHA1(value). For TLS
 * 1.2 SHA256 is used, as described in the RFC. Inspired by the Bouncy Castle
 * CombinedHash class.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public final class TlsMessageDigest {

    private MessageDigest hash1;

    private MessageDigest hash2;

    private byte[] rawBytes = {};

    private boolean initialized;

    /**
     * Default constructor. We use this in cases when we do not know yet, which
     * message digest is going to be computed.
     */
    public TlsMessageDigest() {

    }

    /**
     * Constructor with TLS digest algorithm, incl. its initialization
     * 
     * @param digestAlgorithm
     * @throws NoSuchAlgorithmException
     */
    public TlsMessageDigest(DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException {
	initializeDigestAlgorithm(digestAlgorithm);
    }

    /**
     * Initialization of the message digest algorithm(s). The function in
     * addition computes a digest over the data that is already contained in the
     * raw bytes.
     * 
     * @param digestAlgorithm
     * @throws NoSuchAlgorithmException
     */
    public void initializeDigestAlgorithm(DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException {
	if (initialized) {
	    throw new IllegalStateException("The TLS message digest algorithm has already been set");
	}
	if (digestAlgorithm == DigestAlgorithm.LEGACY) {
	    this.hash1 = MessageDigest.getInstance("MD5");
	    this.hash2 = MessageDigest.getInstance("SHA-1");
	} else {
	    this.hash1 = MessageDigest.getInstance(digestAlgorithm.getJavaName());
	}
	initialized = true;
	updateDigest(rawBytes);
    }

    public String getAlgorithm() {
	String algorithm = hash1.getAlgorithm();
	if (hash2 != null) {
	    algorithm += " and " + hash2.getAlgorithm();
	}
	return algorithm;
    }

    public int getDigestLength() {
	int digestLength = hash1.getDigestLength();
	if (hash2 != null) {
	    digestLength += hash2.getDigestLength();

	}
	return digestLength;
    }

    public void update(byte in) {
	if (initialized) {
	    updateDigest(in);
	}
	byte[] tmp = new byte[1];
	tmp[0] = in;
	rawBytes = ArrayConverter.concatenate(rawBytes, tmp);
    }

    public void updateDigest(byte in) {
	// LOGGER.debug("Updating digest over the following data: \n  {}", in);
	hash1.update(in);
	if (hash2 != null) {
	    hash2.update(in);
	}
    }

    public void update(byte[] in, int inOff, int len) {
	if (initialized) {
	    updateDigest(in, inOff, len);
	}
	rawBytes = ArrayConverter.concatenate(rawBytes, Arrays.copyOfRange(in, inOff, inOff + len));
    }

    public void updateDigest(byte[] in, int inOff, int len) {
	// LOGGER.debug("Updating digest over the following data: \n  {}",
	// ArrayConverter.bytesToHexString(Arrays.copyOfRange(in, inOff, len)));
	hash1.update(in, inOff, len);
	if (hash2 != null) {
	    hash2.update(in, inOff, len);
	}
    }

    public void update(byte[] in) {
	if (initialized) {
	    updateDigest(in);
	}
	rawBytes = ArrayConverter.concatenate(rawBytes, in);
    }

    public void updateDigest(byte[] in) {
	// LOGGER.debug("Updating digest over the following data: \n  {}",
	// ArrayConverter.bytesToHexString(in));
	hash1.update(in);
	if (hash2 != null) {
	    hash2.update(in);
	}
    }

    public byte[] digest() {
	byte[] digest = hash1.digest();
	if (hash2 != null) {
	    byte[] d2 = hash2.digest();
	    digest = ArrayConverter.concatenate(digest, d2);
	}
	// LOGGER.debug("Digest over the data was computed: \n  {}",
	// ArrayConverter.bytesToHexString(digest));
	return digest;
    }

    public void reset() {
	hash1.reset();
	if (hash2 != null) {
	    hash2.reset();
	}
	rawBytes = new byte[0];
    }

    public byte[] getRawBytes() {
	return rawBytes;
    }

    public void setRawBytes(byte[] rawBytes) {
	reset();
	if (rawBytes != null) {
	    this.rawBytes = rawBytes;
	    updateDigest(rawBytes);
	} else {
	    rawBytes = new byte[0];
	}
    }
}
