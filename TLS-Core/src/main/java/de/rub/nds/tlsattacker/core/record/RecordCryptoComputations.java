/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import java.io.Serializable;
import java.util.Objects;

public class RecordCryptoComputations extends ModifiableVariableHolder implements Serializable {

    /** The key used for the symmetric cipher */
    private ModifiableByteArray cipherKey;

    /** The key used for the HMAC */
    private ModifiableByteArray macKey;

    /** The HMAC of the record */
    private ModifiableByteArray mac;

    /** The implicit part of the nonce for aead taken from the keyBlock */
    private ModifiableByteArray aeadSalt;

    /** The explicit nonce for aead which is transmitted in plain in each message */
    private ModifiableByteArray explicitNonce;

    /** The whole gcm nonce (salt || explicit nonce) */
    private ModifiableByteArray gcmNonce;

    /** The whole padding */
    private ModifiableByteArray padding;

    /** The number of padding bytes which should be added beyond the required padding */
    private ModifiableInteger additionalPaddingLength;

    /** The bytes which are going to be passed to the encrypt function */
    private ModifiableByteArray plainRecordBytes;

    /** The bytes of the plain message that are going to be authenticated */
    private ModifiableByteArray authenticatedNonMetaData;

    /** The pure ciphertext part of the record. The output from the negotiated cipher */
    private ModifiableByteArray ciphertext;

    /** The CBC IV */
    private ModifiableByteArray cbcInitialisationVector;

    /** The data over which the HMACs/tags are computed which are not explicitly transmitted. */
    private ModifiableByteArray authenticatedMetaData;

    private ModifiableByteArray authenticationTag;

    private Boolean paddingValid = null;

    private Boolean macValid = null;

    private Boolean authenticationTagValid = null;

    private Tls13KeySetType usedTls13KeySetType = Tls13KeySetType.NONE;

    public RecordCryptoComputations() {}

    @Override
    public void reset() {
        super.reset();
        paddingValid = null;
        macValid = null;
        authenticationTagValid = null;
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
        this.plainRecordBytes =
                ModifiableVariableFactory.safelySetValue(this.plainRecordBytes, plainRecordBytes);
    }

    public ModifiableByteArray getCbcInitialisationVector() {
        return cbcInitialisationVector;
    }

    public void setCbcInitialisationVector(ModifiableByteArray cbcInitialisationVector) {
        this.cbcInitialisationVector = cbcInitialisationVector;
    }

    public void setCbcInitialisationVector(byte[] initialisationVector) {
        this.cbcInitialisationVector =
                ModifiableVariableFactory.safelySetValue(
                        this.cbcInitialisationVector, initialisationVector);
    }

    public ModifiableByteArray getAuthenticatedMetaData() {
        return authenticatedMetaData;
    }

    public void setAuthenticatedMetaData(ModifiableByteArray authenticatedMetaData) {
        this.authenticatedMetaData = authenticatedMetaData;
    }

    public void setAuthenticatedMetaData(byte[] authenticatedMetaData) {
        this.authenticatedMetaData =
                ModifiableVariableFactory.safelySetValue(
                        this.authenticatedMetaData, authenticatedMetaData);
    }

    public ModifiableByteArray getAuthenticatedNonMetaData() {
        return authenticatedNonMetaData;
    }

    public void setAuthenticatedNonMetaData(ModifiableByteArray authenticatedNonMetaData) {
        this.authenticatedNonMetaData = authenticatedNonMetaData;
    }

    public void setAuthenticatedNonMetaData(byte[] authenticatedNonMetaData) {
        this.authenticatedNonMetaData =
                ModifiableVariableFactory.safelySetValue(
                        this.authenticatedNonMetaData, authenticatedNonMetaData);
    }

    public ModifiableInteger getAdditionalPaddingLength() {
        return additionalPaddingLength;
    }

    public void setAdditionalPaddingLength(ModifiableInteger additionalPaddingLength) {
        this.additionalPaddingLength = additionalPaddingLength;
    }

    public void setAdditionalPaddingLength(Integer paddingLength) {
        this.additionalPaddingLength =
                ModifiableVariableFactory.safelySetValue(
                        this.additionalPaddingLength, paddingLength);
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

    public ModifiableByteArray getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(ModifiableByteArray ciphertext) {
        this.ciphertext = ciphertext;
    }

    public void setCiphertext(byte[] ciphertext) {
        this.ciphertext = ModifiableVariableFactory.safelySetValue(this.ciphertext, ciphertext);
    }

    public ModifiableByteArray getAeadSalt() {
        return aeadSalt;
    }

    public void setAeadSalt(ModifiableByteArray aeadSalt) {
        this.aeadSalt = aeadSalt;
    }

    public void setAeadSalt(byte[] aeadSalt) {
        this.aeadSalt = ModifiableVariableFactory.safelySetValue(this.aeadSalt, aeadSalt);
    }

    public ModifiableByteArray getExplicitNonce() {
        return explicitNonce;
    }

    public void setExplicitNonce(ModifiableByteArray explicitNonce) {
        this.explicitNonce = explicitNonce;
    }

    public void setExplicitNonce(byte[] explicitNonce) {
        this.explicitNonce =
                ModifiableVariableFactory.safelySetValue(this.explicitNonce, explicitNonce);
    }

    public ModifiableByteArray getGcmNonce() {
        return gcmNonce;
    }

    public void setGcmNonce(ModifiableByteArray gcmNonce) {
        this.gcmNonce = gcmNonce;
    }

    public void setGcmNonce(byte[] gcmNonce) {
        this.gcmNonce = ModifiableVariableFactory.safelySetValue(this.gcmNonce, gcmNonce);
    }

    public ModifiableByteArray getAuthenticationTag() {
        return authenticationTag;
    }

    public void setAuthenticationTag(ModifiableByteArray authenticationTag) {
        this.authenticationTag = authenticationTag;
    }

    public void setAuthenticationTag(byte[] authenticationTag) {
        this.authenticationTag =
                ModifiableVariableFactory.safelySetValue(this.authenticationTag, authenticationTag);
    }

    public Boolean getAuthenticationTagValid() {
        return authenticationTagValid;
    }

    public void setAuthenticationTagValid(Boolean authenticationTagValid) {
        this.authenticationTagValid = authenticationTagValid;
    }

    public void setAuthenticationTagValid(boolean authenticationTagValid) {
        this.authenticationTagValid = authenticationTagValid;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 31 * hash + Objects.hashCode(this.cipherKey);
        hash = 31 * hash + Objects.hashCode(this.macKey);
        hash = 31 * hash + Objects.hashCode(this.mac);
        hash = 31 * hash + Objects.hashCode(this.aeadSalt);
        hash = 31 * hash + Objects.hashCode(this.explicitNonce);
        hash = 31 * hash + Objects.hashCode(this.gcmNonce);
        hash = 31 * hash + Objects.hashCode(this.padding);
        hash = 31 * hash + Objects.hashCode(this.additionalPaddingLength);
        hash = 31 * hash + Objects.hashCode(this.plainRecordBytes);
        hash = 31 * hash + Objects.hashCode(this.authenticatedNonMetaData);
        hash = 31 * hash + Objects.hashCode(this.ciphertext);
        hash = 31 * hash + Objects.hashCode(this.cbcInitialisationVector);
        hash = 31 * hash + Objects.hashCode(this.authenticatedMetaData);
        hash = 31 * hash + Objects.hashCode(this.authenticationTag);
        hash = 31 * hash + Objects.hashCode(this.paddingValid);
        hash = 31 * hash + Objects.hashCode(this.macValid);
        hash = 31 * hash + Objects.hashCode(this.authenticationTagValid);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final RecordCryptoComputations other = (RecordCryptoComputations) obj;
        if (!Objects.equals(this.cipherKey, other.cipherKey)) {
            return false;
        }
        if (!Objects.equals(this.macKey, other.macKey)) {
            return false;
        }
        if (!Objects.equals(this.mac, other.mac)) {
            return false;
        }
        if (!Objects.equals(this.aeadSalt, other.aeadSalt)) {
            return false;
        }
        if (!Objects.equals(this.explicitNonce, other.explicitNonce)) {
            return false;
        }
        if (!Objects.equals(this.gcmNonce, other.gcmNonce)) {
            return false;
        }
        if (!Objects.equals(this.padding, other.padding)) {
            return false;
        }
        if (!Objects.equals(this.additionalPaddingLength, other.additionalPaddingLength)) {
            return false;
        }
        if (!Objects.equals(this.plainRecordBytes, other.plainRecordBytes)) {
            return false;
        }
        if (!Objects.equals(this.authenticatedNonMetaData, other.authenticatedNonMetaData)) {
            return false;
        }
        if (!Objects.equals(this.ciphertext, other.ciphertext)) {
            return false;
        }
        if (!Objects.equals(this.cbcInitialisationVector, other.cbcInitialisationVector)) {
            return false;
        }
        if (!Objects.equals(this.authenticatedMetaData, other.authenticatedMetaData)) {
            return false;
        }
        if (!Objects.equals(this.authenticationTag, other.authenticationTag)) {
            return false;
        }
        if (!Objects.equals(this.paddingValid, other.paddingValid)) {
            return false;
        }
        if (!Objects.equals(this.macValid, other.macValid)) {
            return false;
        }
        if (!Objects.equals(this.authenticationTagValid, other.authenticationTagValid)) {
            return false;
        }
        return true;
    }

    public Tls13KeySetType getUsedTls13KeySetType() {
        return usedTls13KeySetType;
    }

    public void setUsedTls13KeySetType(Tls13KeySetType usedTls13KeySetType) {
        this.usedTls13KeySetType = usedTls13KeySetType;
    }
}
