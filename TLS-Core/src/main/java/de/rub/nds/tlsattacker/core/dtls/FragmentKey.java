/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

public class FragmentKey {

    private Integer messageSeq;
    private Integer epoch;

    public FragmentKey(Integer messageSeq, Integer epoch) {
        super();
        this.messageSeq = messageSeq;
        this.epoch = epoch;
    }

    public Integer getEpoch() {
        return epoch;
    }

    public Integer getMessageSeq() {
        return messageSeq;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((epoch == null) ? 0 : epoch.hashCode());
        result = prime * result + ((messageSeq == null) ? 0 : messageSeq.hashCode());
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
        FragmentKey other = (FragmentKey) obj;
        if (epoch == null) {
            if (other.epoch != null) {
                return false;
            }
        } else if (!epoch.equals(other.epoch)) {
            return false;
        }
        if (messageSeq == null) {
            if (other.messageSeq != null) {
                return false;
            }
        } else if (!messageSeq.equals(other.messageSeq)) {
            return false;
        }
        return true;
    }

    public String toString() {
        return String.format("Key{messageSeq:%d,epoch:%d}", messageSeq, epoch);
    }
}
