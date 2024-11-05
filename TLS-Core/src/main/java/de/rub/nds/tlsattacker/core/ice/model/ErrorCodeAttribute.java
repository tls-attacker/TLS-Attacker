/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.tlsattacker.core.constants.stun.StunAttributeType;
import de.rub.nds.tlsattacker.core.ice.handler.ErrorCodeAttributeHandler;
import de.rub.nds.tlsattacker.core.ice.parser.ErrorCodeAttributeParser;
import de.rub.nds.tlsattacker.core.ice.preparator.ErrorCodeAttributePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.ErrorCodeAttributeSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

public class ErrorCodeAttribute extends StunAttribute {

    private Integer errorCodeConfig = null;

    private String reasonConfig = null;

    /**
     * In the spec this is 21 bits - we make this 16 bits and make the 4 lsb part of the error code
     * class
     */
    private ModifiableByteArray reservedBytes;

    /** This is the human readable error code that is encoded here */
    private ModifiableInteger number;

    /**
     * Error codes are weirdly encoded in STUN. They are generally numbers between 300 - 699 however
     * they are encoded as two byte values. The first byte is the (decimal) hundreds digit, the last
     * byte is the last two digit.
     */
    private ModifiableByteArray errorCodeClass;

    private ModifiableByteArray errorCodeLowerValue;

    private ModifiableString reasonPhrase;

    public ErrorCodeAttribute() {
        super(StunAttributeType.ERROR_CODE);
    }

    public String getReasonConfig() {
        return reasonConfig;
    }

    public void setReasonConfig(String reasonConfig) {
        this.reasonConfig = reasonConfig;
    }

    public Integer getErrorCodeConfig() {
        return errorCodeConfig;
    }

    public void setErrorCodeConfig(Integer errorCodeConfig) {
        this.errorCodeConfig = errorCodeConfig;
    }

    public ModifiableByteArray getReservedBytes() {
        return reservedBytes;
    }

    public void setReservedBytes(ModifiableByteArray reservedBytes) {
        this.reservedBytes = reservedBytes;
    }

    public ModifiableInteger getNumber() {
        return number;
    }

    public void setNumber(ModifiableInteger number) {
        this.number = number;
    }

    public void setNumber(Integer number) {
        this.number = ModifiableVariableFactory.safelySetValue(this.number, number);
    }

    public ModifiableString getReasonPhrase() {
        return reasonPhrase;
    }

    public void setReasonPhrase(ModifiableString reasonPhrase) {
        this.reasonPhrase = reasonPhrase;
    }

    public void setReasonPhrase(String reasonPhrase) {
        this.reasonPhrase =
                ModifiableVariableFactory.safelySetValue(this.reasonPhrase, reasonPhrase);
    }

    public void setNumber(int number) {
        this.number = ModifiableVariableFactory.safelySetValue(this.number, number);
    }

    public void setReservedByte(byte[] reservedByte) {
        this.reservedBytes =
                ModifiableVariableFactory.safelySetValue(this.reservedBytes, reservedByte);
    }

    public ModifiableByteArray getErrorCodeClass() {
        return errorCodeClass;
    }

    public void setErrorCodeClass(ModifiableByteArray errorCodeClass) {
        this.errorCodeClass = errorCodeClass;
    }

    public void setErrorCodeClass(byte[] errorCodeClass) {
        this.errorCodeClass =
                ModifiableVariableFactory.safelySetValue(this.errorCodeClass, errorCodeClass);
    }

    public ModifiableByteArray getErrorCodeLowerValue() {
        return errorCodeLowerValue;
    }

    public void setErrorCodeLowerValue(ModifiableByteArray errorCodeLowerValue) {
        this.errorCodeLowerValue = errorCodeLowerValue;
    }

    public void setErrorCodeLowerValue(byte[] errorCodeLowerValue) {
        this.errorCodeLowerValue =
                ModifiableVariableFactory.safelySetValue(
                        this.errorCodeLowerValue, errorCodeLowerValue);
    }

    @Override
    public ErrorCodeAttributeParser getParser(Context context, InputStream stream) {
        return new ErrorCodeAttributeParser(context, stream);
    }

    @Override
    public ErrorCodeAttributePreparator getPreparator(Context context) {
        return new ErrorCodeAttributePreparator(context.getChooser(), this);
    }

    @Override
    public ErrorCodeAttributeSerializer getSerializer(Context context) {
        return new ErrorCodeAttributeSerializer(this);
    }

    @Override
    public ErrorCodeAttributeHandler getHandler(Context context) {
        return new ErrorCodeAttributeHandler(context);
    }
}
