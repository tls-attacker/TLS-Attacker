/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.data;

import de.rub.nds.tlsattacker.core.layer.context.LayerContext;

/**
 * The handler is used to adjust the context based on a given DataContainer being processed by a layer.
 * Handlers are often invoked implicitly when using {@link de.rub.nds.tlsattacker.core.layer.ProtocolLayer#readDataContainer ProtocolLayer#readDataContainer}.
 * @param <T> The Object that should be Handled
 */
public abstract class Handler<T extends DataContainer<? extends LayerContext>> {

    public abstract void adjustContext(T container);
}
