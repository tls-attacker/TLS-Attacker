/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

/**
 * Types that can be listed via ListDelegate
 */
public enum ListDelegateType {
    ciphers,
    filters,
    groups,
    sign_hash_algos,
    workflow_trace_types
}
