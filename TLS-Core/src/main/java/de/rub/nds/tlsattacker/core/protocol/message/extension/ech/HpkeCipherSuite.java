/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.ech;

import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyDerivationFunction;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class HpkeCipherSuite implements Serializable {

    private HpkeKeyDerivationFunction hpkeKeyDerivationFunction;
    private HpkeAeadFunction hpkeAeadFunction;

    public HpkeCipherSuite() {}

    public HpkeCipherSuite(
            HpkeKeyDerivationFunction hpkeKeyDerivationFunction,
            HpkeAeadFunction hpkeAeadFunction) {
        this.hpkeKeyDerivationFunction = hpkeKeyDerivationFunction;
        this.hpkeAeadFunction = hpkeAeadFunction;
    }

    public HpkeKeyDerivationFunction getKeyDerivationFunction() {
        return hpkeKeyDerivationFunction;
    }

    public void setKeyDerivationFunction(HpkeKeyDerivationFunction hpkeKeyDerivationFunction) {
        this.hpkeKeyDerivationFunction = hpkeKeyDerivationFunction;
    }

    public HpkeAeadFunction getAeadFunction() {
        return hpkeAeadFunction;
    }

    public void setAeadFunction(HpkeAeadFunction hpkeAeadFunction) {
        this.hpkeAeadFunction = hpkeAeadFunction;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof HpkeCipherSuite)) {
            return false;
        }
        HpkeCipherSuite otherCipherSuite = (HpkeCipherSuite) other;
        return this.hpkeKeyDerivationFunction == otherCipherSuite.hpkeKeyDerivationFunction
                && this.hpkeAeadFunction == otherCipherSuite.hpkeAeadFunction;
    }
}
