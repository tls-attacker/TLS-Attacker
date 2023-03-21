/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.adapter;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.math.BigInteger;

@XmlAccessorType(XmlAccessType.FIELD)
class MapElements {

    @XmlAttribute private NamedGroup key;
    @XmlAttribute private BigInteger value;

    @SuppressWarnings("unused")
    private MapElements() {} // Required by JAXB

    public MapElements(NamedGroup key, BigInteger value) {
        this.key = key;
        this.value = value;
    }

    public NamedGroup getKey() {
        return key;
    }

    public void setKey(NamedGroup key) {
        this.key = key;
    }

    public BigInteger getValue() {
        return value;
    }

    public void setValue(BigInteger value) {
        this.value = value;
    }
}
