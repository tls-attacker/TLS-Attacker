/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https.header;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.https.header.preparator.ContentLengthHeaderPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import javax.xml.bind.annotation.XmlTransient;

public class ContentLengthHeader extends HttpsHeader {

    private ModifiableInteger length;

    @XmlTransient
    private int configLength;

    public ContentLengthHeader() {
    }

    @Override
    public Preparator getPreparator(Chooser chooser) {
        return new ContentLengthHeaderPreparator(chooser, this);
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public int getConfigLength() {
        return configLength;
    }

    public void setConfigLength(int configLength) {
        this.configLength = configLength;
    }

}
