package de.rub.nds.tlsattacker.core.certificate;

import java.util.List;

public class CertificateChainAnalyzer {
   
    private static final Logger LOGGER = LogManager.getLogger();

    public boolean isChainOrdered(X509CertificateChain chain, String uri)
    {

    }   
    
    public boolean containsTrustAnchor(X509CertificateChain chain)
    {

    }

    public boolean containsKnownTrustAnchor(X509CertificateChain chain, List<TrustAnchor> anchor)
    {

    }

    public boolean containsMultipleLeafs(X509CerticficateChain chain)
    {

    }

    public boolean containsValidLeaf(X509CerticficateChain chain)
    {
        
    }

    public List<TrustPath> getAllTrustPaths(X509CertificateChain chain, List<TrustAnchor> trustAnchorList){
    }

    public boolean containsExpiredCertificate(TrustPath path){
    }

    public boolean containsExpiredCertificate(X509CertificateChain chain){
    }

    public boolean containsNotYetValidCertificate(TrustPath path){
    }

    public boolean containsNotYetValidCertificate(X509CertificateChain chain){
    }

    public boolean containsWeakSignature(TrustPath path){
    }

    public boolean containsSelfSignedLeaf(X509CertificateChain chain)
    {

    }

    public boolean hasIncompleteChain(X509CertificateChain chain)
    {
    }

    public boolean allSignaturesValid(X509CertificateChain chain)
    {
    }
}
