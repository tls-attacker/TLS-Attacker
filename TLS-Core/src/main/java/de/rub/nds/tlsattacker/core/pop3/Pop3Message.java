/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3;

import de.rub.nds.tlsattacker.core.layer.Message;
import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.handler.Pop3MessageHandler;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3MessagePreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3MessageSerializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.io.InputStream;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Pop3Message extends Message<Pop3Context> {

    @Override
    public abstract Pop3MessageHandler<? extends Pop3Message> getHandler(Pop3Context pop3Context);

    @Override
    public abstract Pop3MessageParser<? extends Pop3Message> getParser(
            Pop3Context context, InputStream stream);

    @Override
    public abstract Pop3MessagePreparator<? extends Pop3Message> getPreparator(Pop3Context context);

    @Override
    public abstract Pop3MessageSerializer<? extends Pop3Message> getSerializer(Pop3Context context);
}
