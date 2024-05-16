package de.rub.nds.tlsattacker.core.stun.turn.model;

import java.io.InputStream;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.stun.turn.handler.ChannelDataMessageHandler;
import de.rub.nds.tlsattacker.core.stun.turn.parser.ChannelDataMessageParser;
import de.rub.nds.tlsattacker.core.stun.turn.preparator.ChannelDataMessagePreparator;
import de.rub.nds.tlsattacker.core.stun.turn.serializer.ChannelDataMessageSerializer;

public class ChannelDataMessage extends Message<IceContext>{

    private ModifiableByteArray channelNumber;

    private ModifiableInteger messageLength;

    private ModifiableByteArray data;

    public ChannelDataMessage() {
        super();
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
