/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlSeeAlso;

/**
 * Abstract class for different messages the TLS-Attacker can send. This includes but is not limited
 * to TLS-Messages.
 *
 * @param <Self> The message class itself
 * @param <Context> The type of context this message needs to use, relates to the messages' layer.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({Message.class, ProtocolMessage.class, HttpMessage.class})
public abstract class Message<Self extends Message<?, ?>, Context extends LayerContext>
        extends ModifiableVariableHolder implements DataContainer<Self, Context> {

    public abstract String toShortString();
}
