/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.util.SuppressingTrueBooleanAdapter;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.Objects;

/**
 * Abstract class for different messages the TLS-Attacker can send. This includes but is not limited
 * to TLS-Messages.
 *
 * @param <Context> The type of context this message needs to use, relates to the messages' layer.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Message<Context extends LayerContext> extends ModifiableVariableHolder
        implements DataContainer<Context> {

    @XmlJavaTypeAdapter(SuppressingTrueBooleanAdapter.class)
    private Boolean shouldPrepare = null;

    public abstract String toShortString();

    @Override
    public boolean shouldPrepare() {
        return !Objects.equals(shouldPrepare, Boolean.FALSE);
    }

    public void setShouldPrepare(boolean shouldPrepare) {
        this.shouldPrepare = shouldPrepare;
    }
}
