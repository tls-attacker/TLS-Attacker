/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;

/**
 * This extension is defined in RFC6962
 */
public class SignedCertificateTimestampExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableByteArray singedTimestamp;

    /**
     * Constructor
     */
    public SignedCertificateTimestampExtensionMessage() {
        super(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP);
    }

    /**
     * @return the raw signedTimestamp
     */
    public ModifiableByteArray getSignedTimestamp() {
        return singedTimestamp;
    }

    /**
     * @param singedTimestamp
     *            - Timestamp as MidifiableByteArray
     */
    public void setSignedTimestamp(ModifiableByteArray singedTimestamp) {
        this.singedTimestamp = singedTimestamp;
    }

    /**
     * @param singedTimestamp
     *            - Timestamp as byte array
     */
    public void setSignedTimestamp(byte[] singedTimestamp) {
        this.singedTimestamp = ModifiableVariableFactory.safelySetValue(this.singedTimestamp, singedTimestamp);
    }

}
