/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.transport.recording;

import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

public class RecordedLine {

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] recordedMessage;

    public RecordedLine(byte[] recordedMessage) {
        this.recordedMessage = recordedMessage;
    }

    public byte[] getRecordedMessage() {
        return recordedMessage;
    }

    public void setRecordedMessage(byte[] recordedMessage) {
        this.recordedMessage = recordedMessage;
    }
}
