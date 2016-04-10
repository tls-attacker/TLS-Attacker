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
package de.rub.nds.tlsattacker.attacks.ths.oldTHSwithThreads;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import org.bouncycastle.crypto.tls.ServerDHParams;

/**
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TripleHandshakeSharedContext {

    /**
     * premaster secret established during the handshake
     */
    private byte[] preMasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
    /**
     * client random, including unix time
     */
    private byte[] clientRandom = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * server random, including unix time
     */
    private byte[] serverRandom = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];
    /**
     * session ID
     */
    private byte[] sessionID = new byte[HandshakeByteLength.RANDOM + HandshakeByteLength.UNIX_TIME];

    /**
     * Server DH parameters
     */
    private ServerDHParams serverDHParameters;

    public byte[] getPreMasterSecret() {
	return preMasterSecret;
    }

    public void setPreMasterSecret(byte[] preMasterSecret) {
	this.preMasterSecret = preMasterSecret;
    }

    public byte[] getClientRandom() {
	return clientRandom;
    }

    public void setClientRandom(byte[] clientRandom) {
	this.clientRandom = clientRandom;
    }

    public byte[] getServerRandom() {
	return serverRandom;
    }

    public void setServerRandom(byte[] serverRandom) {
	this.serverRandom = serverRandom;
    }

    public byte[] getSessionID() {
	return sessionID;
    }

    public void setSessionID(byte[] sessionID) {
	this.sessionID = sessionID;
    }

    public ServerDHParams getServerDHParameters() {
	return serverDHParameters;
    }

    public void setServerDHParameters(ServerDHParams serverDHParameters) {
	this.serverDHParameters = serverDHParameters;
    }

    public void lock() throws InterruptedException {
	synchronized (this) {
	    wait();
	}
    }

    public void unlockAndWait() throws InterruptedException {
	synchronized (this) {
	    notify();
	    wait();
	}
    }

    public void unlock() throws InterruptedException {
	synchronized (this) {
	    notify();
	}
    }

}