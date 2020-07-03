/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import static de.rub.nds.modifiablevariable.ModifiableVariableFactory.safelySetValue;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;

/**
 * This extension is defined in RFC6066
 */
public class CertificateStatusRequestExtensionMessage extends ExtensionMessage {

    @ModifiableVariableProperty
    private ModifiableInteger certificateStatusRequestType;
    @ModifiableVariableProperty
    private ModifiableInteger responderIDListLength;
    @ModifiableVariableProperty
    private ModifiableByteArray responderIDList;
    @ModifiableVariableProperty
    private ModifiableInteger requestExtensionLength;
    @ModifiableVariableProperty
    private ModifiableByteArray requestExtension;
    /**
     * As a TLS 1.3 CertificateEntry extension, this extension uses the format
     * of a CertificateStatus message. If this is the case, let's treat it as an
     * embedded CertificateStatus message.
     */
    private CertificateStatusMessage certificateStatus;

    public CertificateStatusRequestExtensionMessage() {
        super(ExtensionType.STATUS_REQUEST);
    }

    public ModifiableInteger getCertificateStatusRequestType() {
        return certificateStatusRequestType;
    }

    public void setCertificateStatusRequestType(ModifiableInteger certificateStatusRequestType) {
        this.certificateStatusRequestType = certificateStatusRequestType;
    }

    public void setCertificateStatusRequestType(int certificateStatusRequestType) {
        this.certificateStatusRequestType = safelySetValue(this.certificateStatusRequestType,
                certificateStatusRequestType);
    }

    public ModifiableInteger getResponderIDListLength() {
        return responderIDListLength;
    }

    public void setResponderIDListLength(ModifiableInteger responderIDListLength) {
        this.responderIDListLength = responderIDListLength;
    }

    public void setResponderIDListLength(int responderIDListLength) {
        this.responderIDListLength = safelySetValue(this.responderIDListLength, responderIDListLength);
    }

    public ModifiableByteArray getResponderIDList() {
        return responderIDList;
    }

    public void setResponderIDList(ModifiableByteArray responderIDList) {
        this.responderIDList = responderIDList;
    }

    public void setResponderIDList(byte[] responderIDList) {
        this.responderIDList = safelySetValue(this.responderIDList, responderIDList);
    }

    public ModifiableInteger getRequestExtensionLength() {
        return requestExtensionLength;
    }

    public void setRequestExtensionLength(ModifiableInteger requestExtensionLength) {
        this.requestExtensionLength = requestExtensionLength;
    }

    public void setRequestExtensionLength(int requestExtensionLength) {
        this.requestExtensionLength = safelySetValue(this.requestExtensionLength, requestExtensionLength);
    }

    public ModifiableByteArray getRequestExtension() {
        return requestExtension;
    }

    public void setRequestExtension(ModifiableByteArray requestExtension) {
        this.requestExtension = requestExtension;
    }

    public void setRequestExtension(byte[] requestExtension) {
        this.requestExtension = safelySetValue(this.requestExtension, requestExtension);
    }

    public CertificateStatusMessage getCertificateStatus() {
        return certificateStatus;
    }

    public void setCertificateStatus(CertificateStatusMessage certificateStatus) {
        this.certificateStatus = certificateStatus;
    }
}
