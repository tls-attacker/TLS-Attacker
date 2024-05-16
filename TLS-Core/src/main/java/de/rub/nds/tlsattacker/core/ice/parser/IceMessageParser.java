package de.rub.nds.tlsattacker.core.ice.parser;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.ice.model.IceMessage;
import de.rub.nds.tlsattacker.core.layer.data.Parser;

public abstract class IceMessageParser<MessageT extends IceMessage>
        extends Parser<MessageT> {

    public IceMessageParser(InputStream stream) {
        super(stream);
    }

}
