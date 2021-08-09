/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

public class CcsKey {

    private Integer epoch;

    public CcsKey(Integer epoch) {
        super();
        this.epoch = epoch;
    }

    public Integer getEpoch() {
        return epoch;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((epoch == null) ? 0 : epoch.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        CcsKey other = (CcsKey) obj;
        if (epoch == null) {
            if (other.epoch != null) {
                return false;
            }
        } else if (!epoch.equals(other.epoch)) {
            return false;
        }
        return true;
    }

    public String toString() {
        return String.format("Key{epoch:%d}", epoch);
    }
}
