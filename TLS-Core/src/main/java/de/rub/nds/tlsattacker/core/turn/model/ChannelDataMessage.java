package de.rub.nds.tlsattacker.core.turn.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.stun.IceContext;

public class ChannelDataMessage extends Message<IceContext> {{
    private ModifiableInteger channelNumber;

    private ModifiableInteger length;

    private ModifiableByteArray applicationData;

    public ChannelDataMessage() {
    }

    public ModifiableInteger getChannelNumber() {
        return channelNumber;
    }

    public void setChannelNumber(ModifiableInteger channelNumber) {
        this.channelNumber = channelNumber;
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public ModifiableByteArray getApplicationData() {
        return applicationData;
    }

    public void setApplicationData(ModifiableByteArray applicationData) {
        this.applicationData = applicationData;
    }

    public void setApplicationData(byte[] applicationData) {
        this.applicationData = ModifiableVariableFactory.safelySetValue(this.applicationData, applicationData);
    }

    public void setChannelNumber(int channelNumber) {
        this.channelNumber = ModifiableVariableFactory.safelySetValue(this.channelNumber, channelNumber);
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }
}
