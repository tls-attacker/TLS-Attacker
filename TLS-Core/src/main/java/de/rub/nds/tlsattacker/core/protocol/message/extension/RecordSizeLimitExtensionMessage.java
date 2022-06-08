/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Record Size Limit Extension described in RFC 8449
 */
@XmlRootElement(name = "RecordSizeLimitExtension")
public class RecordSizeLimitExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray recordSizeLimit;

    public RecordSizeLimitExtensionMessage(Config config) {
        super(ExtensionType.RECORD_SIZE_LIMIT);
    }

    public RecordSizeLimitExtensionMessage() {
        super(ExtensionType.RECORD_SIZE_LIMIT);
    }

    public ModifiableByteArray getRecordSizeLimit() {
        return this.recordSizeLimit;
    }

    public void setRecordSizeLimit(ModifiableByteArray recordSizeLimit) {
        this.recordSizeLimit = recordSizeLimit;
    }

    public void setRecordSizeLimit(byte[] recordSizeLimit) {
        this.recordSizeLimit = ModifiableVariableFactory.safelySetValue(this.recordSizeLimit, recordSizeLimit);
    }
}
