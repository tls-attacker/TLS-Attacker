/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.KS;

import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

public class KSEntry {

    private NamedCurve group;

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] serializedPublicKey;

    public KSEntry(NamedCurve group, byte[] serializedPublicKey) {
        this.group = group;
        this.serializedPublicKey = serializedPublicKey;
    }

    public NamedCurve getGroup() {
        return group;
    }

    public void setGroup(NamedCurve group) {
        this.group = group;
    }

    public byte[] getSerializedPublicKey() {
        return serializedPublicKey;
    }

    public void setSerializedPublicKey(byte[] serializedPublicKey) {
        this.serializedPublicKey = serializedPublicKey;
    }

}
