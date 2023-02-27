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
import jakarta.xml.bind.annotation.adapters.XmlAdapter;
import java.math.BigInteger;
import java.util.Map;
import java.util.TreeMap;

public class MapAdapter extends XmlAdapter<MapElements[], Map<NamedGroup, BigInteger>> {

    public MapAdapter() {}

    public MapElements[] marshal(Map<NamedGroup, BigInteger> arg0) throws Exception {
        if (arg0 == null) {
            return new MapElements[0];
        }
        MapElements[] mapElements = new MapElements[arg0.size()];
        int i = 0;
        for (Map.Entry<NamedGroup, BigInteger> entry : arg0.entrySet()) {
            mapElements[i++] = new MapElements(entry.getKey(), entry.getValue());
        }

        return mapElements;
    }

    public Map<NamedGroup, BigInteger> unmarshal(MapElements[] arg0) throws Exception {
        Map<NamedGroup, BigInteger> r = new TreeMap<>();
        for (MapElements mapelement : arg0) {
            r.put(mapelement.getKey(), mapelement.getValue());
        }
        return r;
    }
}
