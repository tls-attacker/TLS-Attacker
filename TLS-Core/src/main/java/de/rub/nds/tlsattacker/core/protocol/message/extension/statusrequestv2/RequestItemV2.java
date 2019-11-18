/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import static de.rub.nds.modifiablevariable.ModifiableVariableFactory.safelySetValue;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import java.io.Serializable;
import java.util.List;

public class RequestItemV2 implements Serializable {

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

    Integer requestTypeConfig;
    Integer requestLengthConfig;
    Integer responderIdListLengthConfig;
    Integer requestExtensionLengthConfig;
    byte[] requestExtensionsConfig;

    public RequestItemV2() {
    }

    public RequestItemV2(Integer preparatorRequestType, Integer preparatorRequestLength,
            Integer preparatorResponderIdListLength, Integer preparatorRequestExtensionLength,
            byte[] preparatorRequestExtensions) {
        this.requestTypeConfig = preparatorRequestType;
        this.requestLengthConfig = preparatorRequestLength;
        this.responderIdListLengthConfig = preparatorResponderIdListLength;
        this.requestExtensionLengthConfig = preparatorRequestExtensionLength;
        this.requestExtensionsConfig = preparatorRequestExtensions;
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

    public Integer getRequestTypeConfig() {
        return requestTypeConfig;
    }

    public void setRequestTypeConfig(Integer requestTypeConfig) {
        this.requestTypeConfig = requestTypeConfig;
    }

    public Integer getRequestLengthConfig() {
        return requestLengthConfig;
    }

    public void setRequestLengthConfig(Integer requestLengthConfig) {
        this.requestLengthConfig = requestLengthConfig;
    }

    public Integer getResponderIdListLengthConfig() {
        return responderIdListLengthConfig;
    }

    public void setResponderIdListLengthConfig(Integer responderIdListLengthConfig) {
        this.responderIdListLengthConfig = responderIdListLengthConfig;
    }

    public Integer getRequestExtensionLengthConfig() {
        return requestExtensionLengthConfig;
    }

    public void setRequestExtensionLengthConfig(Integer requestExtensionLengthConfig) {
        this.requestExtensionLengthConfig = requestExtensionLengthConfig;
    }

    public byte[] getRequestExtensionsConfig() {
        return requestExtensionsConfig;
    }

    public void setRequestExtensionsConfig(byte[] requestExtensionsConfig) {
        this.requestExtensionsConfig = requestExtensionsConfig;
    }

}
