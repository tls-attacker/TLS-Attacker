package de.rub.nds.tlsattacker.core.ice.model;

import java.io.InputStream;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.ice.handler.ChannelDataMessageHandler;
import de.rub.nds.tlsattacker.core.ice.parser.ChannelDataMessageParser;
import de.rub.nds.tlsattacker.core.ice.preparator.ChannelDataMessagePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.ChannelDataMessageSerializer;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;

public class ChannelDataMessage extends IceMessage {

    private ModifiableByteArray channelNumber;

    private ModifiableInteger messageLength;

    private ModifiableByteArray data;

    private byte[] dataConfig;

    public ChannelDataMessage(byte[] dataConfig) {
        super();
        this.dataConfig = dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public ModifiableByteArray getChannelNumber() {
        return channelNumber;
    }

    public void setChannelNumber(ModifiableByteArray channelNumber) {
        this.channelNumber = channelNumber;
    }

    public void setChannelNumber(byte[] channelNumber) {
        this.channelNumber = ModifiableVariableFactory.safelySetValue(this.channelNumber, channelNumber);
    }

    public ModifiableInteger getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(ModifiableInteger messageLength) {
        this.messageLength = messageLength;
    }

    public void setMessageLength(int messageLength) {
        this.messageLength = ModifiableVariableFactory.safelySetValue(this.messageLength, messageLength);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public ChannelDataMessageParser getParser(IceContext context, InputStream stream) {
        return new ChannelDataMessageParser(stream);
    }

    @Override
    public ChannelDataMessagePreparator getPreparator(IceContext context) {
        return new ChannelDataMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelDataMessageSerializer getSerializer(IceContext context) {
        return new ChannelDataMessageSerializer(this);
    }

    @Override
    public ChannelDataMessageHandler getHandler(IceContext context) {
        return new ChannelDataMessageHandler();
    }

    @Override
    public String toShortString() {
        return "ChannelDataMessage";
    }

}
