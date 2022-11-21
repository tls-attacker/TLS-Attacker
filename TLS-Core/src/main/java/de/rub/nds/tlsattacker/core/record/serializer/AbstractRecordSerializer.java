/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.serializer;

import de.rub.nds.tlsattacker.core.protocol.Serializer;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;

/**
 * @param <AbstractRecordT>
 *                          The AbstractRecord that should be serialized
 */
public abstract class AbstractRecordSerializer<AbstractRecordT extends AbstractRecord>
    extends Serializer<AbstractRecordT> {

}
