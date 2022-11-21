/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ResponderIdPreparator extends Preparator<ResponderId> {

    private final ResponderId object;

    public ResponderIdPreparator(Chooser chooser, ResponderId object) {
        super(chooser, object);
        this.object = object;
    }

    @Override
    public void prepare() {
        object.setId(object.getIdConfig());
        object.setIdLength(object.getIdLengthConfig());
    }

}
