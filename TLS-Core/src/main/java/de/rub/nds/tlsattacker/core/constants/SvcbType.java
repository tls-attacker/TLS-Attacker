/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

/** https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/ specifies the SVCB DNS type */
public enum SvcbType {
    MANDATORY(0),
    ALPN(1),
    NO_DEFAULT_ALPN(2),
    PORT(3),
    IPV4HINT(4),
    ECH(5),
    IPV6HINT(6),
    INVALID_KEY(65535);

    private final Integer code;

    private SvcbType(Integer code) {
        this.code = code;
    }

    public Integer getCode() {
        return code;
    }
}
