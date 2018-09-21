/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T>
 *            The Object that should be prepared
 */
public abstract class Preparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Chooser chooser;
    private final T object;

    public Preparator(Chooser chooser, T object) {
        this.chooser = chooser;
        this.object = object;
        if (object == null) {
            throw new PreparationException("Cannot prepare NULL");
        }
    }

    public abstract void prepare();

    public T getObject() {
        return object;
    }

    public void afterPrepare() {

    }

}
