package de.rub.nds.tlsattacker.core.pop3.serializer;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;

public abstract class Pop3MessageSerializer<MesssageT extends Pop3Message> extends Serializer<MesssageT> {

    protected final MesssageT message;
    protected final Pop3Context context;

    public Pop3MessageSerializer(MesssageT message, Pop3Context context) {
        this.message = message;
        this.context = context;
    }

    public MesssageT getMessage() {return message;}

    public Pop3Context getContext() {return context;}
}
