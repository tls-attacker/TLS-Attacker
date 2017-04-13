/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.compressor;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public abstract class Compressor<T> {

    public abstract void compress(T object);
}
