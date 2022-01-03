/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * RFC 6961
 */
@XmlRootElement(name = "CertificateStatusRequestV2Extension")
public class CertificateStatusRequestV2ExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    ModifiableInteger statusRequestListLength;
    @HoldsModifiableVariable
    List<RequestItemV2> statusRequestList;
    @ModifiableVariableProperty
    ModifiableByteArray statusRequestBytes;

    public CertificateStatusRequestV2ExtensionMessage() {
        super(ExtensionType.STATUS_REQUEST_V2);
    }

    public CertificateStatusRequestV2ExtensionMessage(Config config) {
        super(ExtensionType.STATUS_REQUEST_V2);
    }

    public ModifiableInteger getStatusRequestListLength() {
        return statusRequestListLength;
    }

    public void setStatusRequestListLength(ModifiableInteger statusRequestListLength) {
        this.statusRequestListLength = statusRequestListLength;
    }

    public void setStatusRequestListLength(int statusRequestListLength) {
        this.statusRequestListLength =
            ModifiableVariableFactory.safelySetValue(this.statusRequestListLength, statusRequestListLength);
    }

    public List<RequestItemV2> getStatusRequestList() {
        return statusRequestList;
    }

    public void setStatusRequestList(List<RequestItemV2> statusRequestList) {
        this.statusRequestList = statusRequestList;
    }

    public ModifiableByteArray getStatusRequestBytes() {
        return statusRequestBytes;
    }

    public void setStatusRequestBytes(ModifiableByteArray statusRequestBytes) {
        this.statusRequestBytes = statusRequestBytes;
    }

    public void setStatusRequestBytes(byte[] statusRequestBytes) {
        this.statusRequestBytes = ModifiableVariableFactory.safelySetValue(this.statusRequestBytes, statusRequestBytes);
    }
}
