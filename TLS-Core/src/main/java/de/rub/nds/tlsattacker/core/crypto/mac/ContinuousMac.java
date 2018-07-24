/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.mac;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.util.Memoable;

public class ContinuousMac implements WrappedMac {

    private Mac mac;
    private Memoable underlying;

    public ContinuousMac(Mac mac, Memoable underlying, CipherParameters parameters) {
        this.mac = mac;
        this.underlying = underlying;

        mac.init(parameters);
    }

    public <T extends Mac & Memoable> ContinuousMac(T mac, CipherParameters parameters) {
        this(mac, mac, parameters);
    }

    @Override
    public byte[] calculateMac(byte[] data) {
        mac.update(data, 0, data.length);
        Memoable memoable = underlying.copy();
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        underlying.reset(memoable);
        return out;
    }

    @Override
    public int getMacLength() {
        return mac.getMacSize();
    }

}
