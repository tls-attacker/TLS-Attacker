/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package TestVector;

import Modification.Modification;
import Mutator.ServerCertificateKeypair;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TestVector implements Serializable
{

    private WorkflowTrace trace = null;
    private ServerCertificateKeypair keyCertPair = null;
    @XmlTransient
    private TestVector parent = null;
    @XmlTransient
    private long children = 0; // TODO
    @XmlTransient
    private List<Modification> modificationList = null;

    public TestVector(WorkflowTrace trace, ServerCertificateKeypair keyCertPair, TestVector parent)
    {
        this.trace = trace;
        this.keyCertPair = keyCertPair;
        this.parent = parent;
        this.modificationList = new LinkedList<Modification>();
    }

    public TestVector()
    {
    }

    public WorkflowTrace getTrace()
    {
        return trace;
    }

    public ServerCertificateKeypair getKeyCertPair()
    {
        return keyCertPair;
    }

    public void addModification(Modification modification)
    {
        if (modification != null)
        {
            modificationList.add(modification);
        }
    }

    public List<Modification> getModificationList()
    {
        return modificationList;
    }

}
