/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.util;

import jakarta.xml.bind.annotation.adapters.XmlAdapter;
import java.util.Objects;

public class SuppressingTrueBooleanAdapter extends XmlAdapter<String, Boolean> {
    @Override
    public Boolean unmarshal(String v) throws Exception {
        if (v == null) {
            return Boolean.TRUE;
        } else {
            return Boolean.parseBoolean(v);
        }
    }

    @Override
    public String marshal(Boolean v) throws Exception {

        if (Objects.equals(v, Boolean.FALSE)) {
            return v.toString();
        }
        return null;
    }
}
