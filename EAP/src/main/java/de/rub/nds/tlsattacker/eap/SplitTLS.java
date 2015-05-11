/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Felix Lange
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
package de.rub.nds.tlsattacker.eap;

import java.nio.ByteBuffer;

public class SplitTLS {

    byte[] sslraw;

    byte[][] clientresponse;

    private static SplitTLS splittls = new SplitTLS();

    private SplitTLS() {
    }

    public static SplitTLS getInstance() {
	return splittls;
    }

    public byte[][] split(byte[] sslraw) {

	int i, fragmentsize = 1024;
	this.sslraw = sslraw;

	i = (sslraw.length / fragmentsize) + 1;
	clientresponse = new byte[i][];

	for (int y = 0; y < i; y++) {

	    if (y < (i - 1)) {

		clientresponse[y] = new byte[fragmentsize];
		System.arraycopy(sslraw, y * fragmentsize, clientresponse[y], 0, fragmentsize);

	    } else {

		clientresponse[y] = new byte[sslraw.length - (y * fragmentsize)];
		System.arraycopy(sslraw, y * fragmentsize, clientresponse[y], 0, sslraw.length - (y * fragmentsize));

	    }

	}

	return clientresponse;

    }

    public byte[] getFragment(int count) {

	return clientresponse[count];

    }

    public byte[] getSize() {

	int size = 0;

	size = sslraw.length;

	return intToBytes(size);

    }

    public int getSizeInt() {

	int size = 0;

	size = sslraw.length;

	return size;

    }

    public int getCountPacket() {

	int size = 0;

	size = clientresponse.length;

	return size;

    }

    public byte[] intToBytes(final int i) {
	ByteBuffer bb = ByteBuffer.allocate(4);
	bb.putInt(i);
	return bb.array();
    }

}
