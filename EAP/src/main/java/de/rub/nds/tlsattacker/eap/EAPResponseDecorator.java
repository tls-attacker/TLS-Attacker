/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.eap;

/**
 * Abstract Class for EAP-Response Decorator
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public abstract class EAPResponseDecorator extends EAPFrame {

    @Override
    public abstract byte[] getFrame();

    @Override
    public abstract void createFrame();
}
