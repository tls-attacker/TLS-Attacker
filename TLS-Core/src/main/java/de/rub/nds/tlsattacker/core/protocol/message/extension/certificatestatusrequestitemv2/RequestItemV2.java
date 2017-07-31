/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.certificatestatusrequestitemv2;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import static de.rub.nds.modifiablevariable.ModifiableVariableFactory.safelySetValue;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import java.util.List;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class RequestItemV2 {

    @ModifiableVariableProperty
    ModifiableInteger requestType;
    @ModifiableVariableProperty
    ModifiableInteger requestLength;
    @ModifiableVariableProperty
    ModifiableInteger responderIdListLength;
    @HoldsModifiableVariable
    List<ResponderId> responderIdList;
    @ModifiableVariableProperty
    ModifiableInteger requestExtensionsLength;
    @ModifiableVariableProperty
    ModifiableByteArray requestExtensions;
    @ModifiableVariableProperty
    ModifiableByteArray responderIdListBytes;

    Integer preparatorRequestType;
    Integer preparatorRequestLength;
    Integer preparatorResponderIdListLength;
    Integer preparatorRequestExtensionLength;
    byte[] preparatorRequestExtensions;

    public RequestItemV2() {
    }

    public RequestItemV2(Integer preparatorRequestType, Integer preparatorRequestLength,
            Integer preparatorResponderIdListLength, Integer preparatorRequestExtensionLength,
            byte[] preparatorRequestExtensions) {
        this.preparatorRequestType = preparatorRequestType;
        this.preparatorRequestLength = preparatorRequestLength;
        this.preparatorResponderIdListLength = preparatorResponderIdListLength;
        this.preparatorRequestExtensionLength = preparatorRequestExtensionLength;
        this.preparatorRequestExtensions = preparatorRequestExtensions;
    }

    public ModifiableInteger getRequestType() {
        return requestType;
    }

    public void setRequestType(ModifiableInteger requestType) {
        this.requestType = requestType;
    }

    public void setRequestType(int requestType) {
        this.requestType = ModifiableVariableFactory.safelySetValue(this.requestType, requestType);
    }

    public ModifiableInteger getResponderIdListLength() {
        return responderIdListLength;
    }

    public void setResponderIdListLength(ModifiableInteger responderIdListLength) {
        this.responderIdListLength = responderIdListLength;
    }

    public void setResponderIdListLength(int responderIdListLength) {
        this.responderIdListLength = ModifiableVariableFactory.safelySetValue(this.responderIdListLength,
                responderIdListLength);
    }

    public List<ResponderId> getResponderIdList() {
        return responderIdList;
    }

    public void setResponderIdList(List<ResponderId> responderIdList) {
        this.responderIdList = responderIdList;
    }

    public ModifiableInteger getRequestExtensionsLength() {
        return requestExtensionsLength;
    }

    public void setRequestExtensionsLength(ModifiableInteger requestExtensionsLength) {
        this.requestExtensionsLength = requestExtensionsLength;
    }

    public void setRequestExtensionsLength(int requestExtensionsLength) {
        this.requestExtensionsLength = ModifiableVariableFactory.safelySetValue(this.requestExtensionsLength,
                requestExtensionsLength);
    }

    public ModifiableByteArray getRequestExtensions() {
        return requestExtensions;
    }

    public void setRequestExtensions(ModifiableByteArray requestExtensions) {
        this.requestExtensions = requestExtensions;
    }

    public void setRequestExtensions(byte[] requestExtensions) {
        this.requestExtensions = ModifiableVariableFactory.safelySetValue(this.requestExtensions, requestExtensions);
    }

    public ModifiableByteArray getResponderIdListBytes() {
        return responderIdListBytes;
    }

    public void setResponderIdListBytes(ModifiableByteArray responderIdListBytes) {
        this.responderIdListBytes = responderIdListBytes;
    }

    public void setResponderIdListBytes(byte[] responderIdListBytes) {
        this.responderIdListBytes = ModifiableVariableFactory.safelySetValue(this.responderIdListBytes,
                responderIdListBytes);
    }

    public ModifiableInteger getRequestLength() {
        return requestLength;
    }

    public void setRequestLength(ModifiableInteger requestLength) {
        this.requestLength = requestLength;
    }

    public void setRequestLength(int requestLength) {
        this.requestLength = safelySetValue(this.requestLength, requestLength);
    }

    public Integer getPreparatorRequestType() {
        return preparatorRequestType;
    }

    public void setPreparatorRequestType(Integer preparatorRequestType) {
        this.preparatorRequestType = preparatorRequestType;
    }

    public Integer getPreparatorRequestLength() {
        return preparatorRequestLength;
    }

    public void setPreparatorRequestLength(Integer preparatorRequestLength) {
        this.preparatorRequestLength = preparatorRequestLength;
    }

    public Integer getPreparatorResponderIdListLength() {
        return preparatorResponderIdListLength;
    }

    public void setPreparatorResponderIdListLength(Integer preparatorResponderIdListLength) {
        this.preparatorResponderIdListLength = preparatorResponderIdListLength;
    }

    public Integer getPreparatorRequestExtensionLength() {
        return preparatorRequestExtensionLength;
    }

    public void setPreparatorRequestExtensionLength(Integer preparatorRequestExtensionLength) {
        this.preparatorRequestExtensionLength = preparatorRequestExtensionLength;
    }

    public byte[] getPreparatorRequestExtensions() {
        return preparatorRequestExtensions;
    }

    public void setPreparatorRequestExtensions(byte[] preparatorRequestExtensions) {
        this.preparatorRequestExtensions = preparatorRequestExtensions;
    }

}
