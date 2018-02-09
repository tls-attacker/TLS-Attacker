/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import java.math.BigInteger;

public class RecordCryptoComputations {

    private ModifiableByteArray cipherKey;

    private ModifiableByteArray macKey;

    private ModifiableByteArray mac;

    private ModifiableByteArray padding;

    private ModifiableInteger paddingLength;

    private ModifiableByteArray plainRecordBytes;

    private ModifiableByteArray unpaddedRecordBytes;

    private ModifiableByteArray initialisationVector;

    private ModifiableBigInteger sequenceNumber;

    private ModifiableByteArray nonMetaDataMaced;

    private ModifiableByteArray authenticatedMetaData;

    private Boolean paddingValid = null;

    private Boolean macValid = null;

    public RecordCryptoComputations() {
    }

    public ModifiableByteArray getCipherKey() {
        return cipherKey;
    }

    public void setCipherKey(ModifiableByteArray cipherKey) {
        this.cipherKey = cipherKey;
    }

    public void setCipherKey(byte[] cipherKey) {
        this.cipherKey = ModifiableVariableFactory.safelySetValue(this.cipherKey, cipherKey);
    }

    public ModifiableByteArray getMacKey() {
        return macKey;
    }

    public void setMacKey(ModifiableByteArray macKey) {
        this.macKey = macKey;
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = ModifiableVariableFactory.safelySetValue(this.macKey, macKey);
    }

    public ModifiableByteArray getMac() {
        return mac;
    }

    public void setMac(ModifiableByteArray mac) {
        this.mac = mac;
    }

    public void setMac(byte[] mac) {
        this.mac = ModifiableVariableFactory.safelySetValue(this.mac, mac);
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    public ModifiableByteArray getPlainRecordBytes() {
        return plainRecordBytes;
    }

    public void setPlainRecordBytes(ModifiableByteArray plainRecordBytes) {
        this.plainRecordBytes = plainRecordBytes;
    }

    public void setPlainRecordBytes(byte[] plainRecordBytes) {
        this.plainRecordBytes = ModifiableVariableFactory.safelySetValue(this.plainRecordBytes, plainRecordBytes);
    }

    public ModifiableByteArray getUnpaddedRecordBytes() {
        return unpaddedRecordBytes;
    }

    public void setUnpaddedRecordBytes(ModifiableByteArray unpaddedRecordBytes) {
        this.unpaddedRecordBytes = unpaddedRecordBytes;
    }

    public void setUnpaddedRecordBytes(byte[] unpaddedRecordBytes) {
        this.unpaddedRecordBytes = ModifiableVariableFactory.safelySetValue(this.unpaddedRecordBytes,
                unpaddedRecordBytes);
    }

    public ModifiableByteArray getInitialisationVector() {
        return initialisationVector;
    }

    public void setInitialisationVector(ModifiableByteArray initialisationVector) {
        this.initialisationVector = initialisationVector;
    }

    public void setInitialisationVector(byte[] initialisationVector) {
        this.initialisationVector = ModifiableVariableFactory.safelySetValue(this.initialisationVector,
                initialisationVector);
    }

    public ModifiableBigInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableBigInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(BigInteger sequenceNumber) {
        this.sequenceNumber = ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    public ModifiableByteArray getNonMetaDataMaced() {
        return nonMetaDataMaced;
    }

    public void setNonMetaDataMaced(ModifiableByteArray nonMetaDataMaced) {
        this.nonMetaDataMaced = nonMetaDataMaced;
    }

    public void setNonMetaDataMaced(byte[] nonMetaDataMaced) {
        this.nonMetaDataMaced = ModifiableVariableFactory.safelySetValue(this.nonMetaDataMaced, nonMetaDataMaced);
    }

    public ModifiableByteArray getAuthenticatedMetaData() {
        return authenticatedMetaData;
    }

    public void setAuthenticatedMetaData(ModifiableByteArray authenticatedMetaData) {
        this.authenticatedMetaData = authenticatedMetaData;
    }

    public void setAuthenticatedMetaData(byte[] authenticatedMetaData) {
        this.authenticatedMetaData = ModifiableVariableFactory.safelySetValue(this.authenticatedMetaData,
                authenticatedMetaData);
    }

    public ModifiableInteger getPaddingLength() {
        return paddingLength;
    }

    public void setPaddingLength(ModifiableInteger paddingLength) {
        this.paddingLength = paddingLength;
    }

    public void setPaddingLength(Integer paddingLength) {
        this.paddingLength = ModifiableVariableFactory.safelySetValue(this.paddingLength, paddingLength);
    }

    public Boolean getPaddingValid() {
        return paddingValid;
    }

    public void setPaddingValid(Boolean paddingValid) {
        this.paddingValid = paddingValid;
    }

    public Boolean getMacValid() {
        return macValid;
    }

    public void setMacValid(Boolean macValid) {
        this.macValid = macValid;
    }
}
