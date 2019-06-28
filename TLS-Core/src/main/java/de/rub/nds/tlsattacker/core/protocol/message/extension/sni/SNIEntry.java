/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.sni;

import de.rub.nds.tlsattacker.core.constants.NameType;
import java.io.Serializable;
import java.util.Objects;

public class SNIEntry implements Serializable {

    private String name;
    private NameType type;

    public SNIEntry() {
    }

    public SNIEntry(SNIEntry other) {
        name = other.name;
        type = other.type;
    }

    public SNIEntry(String name, NameType type) {
        this.name = name;
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public NameType getType() {
        return type;
    }

    public void setType(NameType type) {
        this.type = type;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + Objects.hashCode(this.name);
        hash = 53 * hash + Objects.hashCode(this.type);
        return hash;
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
        final SNIEntry other = (SNIEntry) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        return this.type == other.type;
    }

}
