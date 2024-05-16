package de.rub.nds.tlsattacker.core.ice.model;

import java.io.InputStream;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.ice.handler.IceMessageHandler;
import de.rub.nds.tlsattacker.core.ice.parser.IceMessageParser;
import de.rub.nds.tlsattacker.core.ice.preparator.IceMessagePreparator;
import de.rub.nds.tlsattacker.core.ice.serializer.IceMessageSerializer;
import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;

public abstract class IceMessage extends Message<IceContext> {

    private ModifiableByteArray completeMessageBytes;

    public ModifiableByteArray getCompleteMessageBytes() {
        return completeMessageBytes;
    }

    public void setCompleteMessageBytes(ModifiableByteArray completeMessageBytes) {
        this.completeMessageBytes = completeMessageBytes;
    }

    public void setCompleteMessageBytes(byte[] completeMessageBytes) {
        this.completeMessageBytes = ModifiableVariableFactory.safelySetValue(this.completeMessageBytes,
                completeMessageBytes);
    }

        @Override
    public abstract IceMessageHandler<? extends IceMessage> getHandler(IceContext context);

    @Override
    public abstract IceMessageParser<? extends IceMessage> getParser(
            IceContext context, InputStream stream);

    @Override
    public abstract IceMessagePreparator<? extends IceMessage> getPreparator(
            IceContext context);

    @Override
    public abstract IceMessageSerializer<? extends IceMessage> getSerializer(
            IceContext context);
}
