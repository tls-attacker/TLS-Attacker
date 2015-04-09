/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Computes message digest for two algorithms at once, typically for MD5 and
 * SHA1 for TLS 1.0. At the end it returns MD5(value) || SHA1(value). For TLS
 * 1.2 SHA256 is used, as described in the RFC. Inspired by the Bouncy Castle
 * CombinedHash class.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class TlsMessageDigest {

    private static final Logger LOGGER = LogManager.getLogger(TlsMessageDigest.class);

    private MessageDigest hash1;

    private MessageDigest hash2;

    private byte[] rawBytes;

    public TlsMessageDigest() throws NoSuchAlgorithmException {
	this.hash1 = MessageDigest.getInstance("MD5");
	this.hash2 = MessageDigest.getInstance("SHA-1");
    }

    public TlsMessageDigest(String hashAlgorithm1, String hashAlgorithm2) throws NoSuchAlgorithmException {
	this.hash1 = MessageDigest.getInstance(hashAlgorithm1);
	this.hash2 = MessageDigest.getInstance(hashAlgorithm2);
    }

    public TlsMessageDigest(String hashAlgorithm1) throws NoSuchAlgorithmException {
	this.hash1 = MessageDigest.getInstance(hashAlgorithm1);
    }

    /**
     * @param protocolVersion
     * @throws NoSuchAlgorithmException
     */
    public TlsMessageDigest(ProtocolVersion protocolVersion) throws NoSuchAlgorithmException {
	if (protocolVersion == ProtocolVersion.TLS12) {
	    // TODO this can cause problems if TLS1.2 cipher suite does not use
	    // sha-256
	    // most of the ciphersuite however use sha256, no problem for now
	    this.hash1 = MessageDigest.getInstance("SHA-256");
	} else {
	    this.hash1 = MessageDigest.getInstance("MD5");
	    this.hash2 = MessageDigest.getInstance("SHA-1");
	}
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
	// LOGGER.debug("Updating digest over the following data: \n  {}", in);
	hash1.update(in);
	if (hash2 != null) {
	    hash2.update(in);
	}
	byte[] tmp = new byte[1];
	tmp[0] = in;
	rawBytes = ArrayConverter.concatenate(rawBytes, tmp);
    }

    public void update(byte[] in, int inOff, int len) {
	// LOGGER.debug("Updating digest over the following data: \n  {}",
	// ArrayConverter.bytesToHexString(Arrays.copyOfRange(in, inOff, len)));
	hash1.update(in, inOff, len);
	if (hash2 != null) {
	    hash2.update(in, inOff, len);
	}
	rawBytes = ArrayConverter.concatenate(rawBytes, Arrays.copyOfRange(in, inOff, inOff + len));
    }

    public void update(byte[] in) {
	// LOGGER.debug("Updating digest over the following data: \n  {}",
	// ArrayConverter.bytesToHexString(in));
	hash1.update(in);
	if (hash2 != null) {
	    hash2.update(in);
	}
	rawBytes = ArrayConverter.concatenate(rawBytes, in);
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
	this.rawBytes = rawBytes;
    }
}
