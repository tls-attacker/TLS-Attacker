/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action.executor;

public enum ActionOption {
    EARLY_CLEAN_SHUTDOWN,
    IGNORE_UNEXPECTED_NEW_SESSION_TICKETS,
    IGNORE_UNEXPECTED_WARNINGS,
    MAY_FAIL,
    CHECK_ONLY_EXPECTED;
}
