/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.record.serializer;

import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

/**
 * @param <AbstractRecordT>
 * The AbstractRecord that should be serialized
 */
public abstract class AbstractRecordSerializer<AbstractRecordT> extends Serializer<AbstractRecordT> {

}
