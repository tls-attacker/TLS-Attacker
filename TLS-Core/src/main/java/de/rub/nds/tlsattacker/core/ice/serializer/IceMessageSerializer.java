package de.rub.nds.tlsattacker.core.ice.serializer;

import de.rub.nds.tlsattacker.core.ice.model.IceMessage;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;

public abstract class IceMessageSerializer<MessageT extends IceMessage>
        extends Serializer<MessageT> {

}
