package org.spongycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.cms.AttributeTable;
import org.spongycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.spongycastle.asn1.smime.SMIMECapability;
import org.spongycastle.asn1.smime.SMIMECapabilityVector;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cms.SignerInformation;
import org.spongycastle.cms.SignerInformationStore;
import org.spongycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.spongycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.spongycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.spongycastle.cms.jcajce.ZlibCompressor;
import org.spongycastle.cms.jcajce.ZlibExpanderProvider;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.mail.smime.SMIMECompressed;
import org.spongycastle.mail.smime.SMIMECompressedGenerator;
import org.spongycastle.mail.smime.SMIMECompressedParser;
import org.spongycastle.mail.smime.SMIMESigned;
import org.spongycastle.mail.smime.SMIMESignedGenerator;
import org.spongycastle.mail.smime.SMIMEUtil;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.Store;

public class SMIMECompressedTest
    extends TestCase
{
    private static final String COMPRESSED_CONTENT_TYPE = "application/pkcs7-mime; name=\"smime.p7z\"; smime-type=compressed-data";

    private static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

    static
    {
        if (Security.getProvider("SC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    boolean DEBUG = true;

    MimeBodyPart    msg;

    String          signDN;
    KeyPair         signKP;
    X509Certificate signCert;

    String          origDN;
    KeyPair         origKP;
    X509Certificate origCert;

    String          reciDN;
    KeyPair         reciKP;
    X509Certificate reciCert;

    KeyPair         dsaSignKP;
    X509Certificate dsaSignCert;

    KeyPair         dsaOrigKP;
    X509Certificate dsaOrigCert;

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public SMIMECompressedTest(
         String name)
        throws Exception
    {
        super(name);
        
        msg      = SMIMETestUtil.makeMimeBodyPart("Hello world!");

        signDN   = "O=Bouncy Castle, C=AU";
        signKP   = CMSTestUtil.makeKeyPair();
        signCert = CMSTestUtil.makeCertificate(signKP, signDN, signKP, signDN);

        origDN   = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        origKP   = CMSTestUtil.makeKeyPair();
        origCert = CMSTestUtil.makeCertificate(origKP, origDN, signKP, signDN);
    }

    public static void main(String args[]) 
    {
        junit.textui.TestRunner.run(SMIMECompressedTest.class);
    }

    public static Test suite() 
    {
        return new SMIMETestSetup(new TestSuite(SMIMECompressedTest.class));
    }

    public void testHeaders()
        throws Exception
    {
        SMIMECompressedGenerator    cgen = new SMIMECompressedGenerator();

        MimeBodyPart cbp = cgen.generate(msg, new ZlibCompressor());
        
        assertEquals(COMPRESSED_CONTENT_TYPE, cbp.getHeader("Content-Type")[0]);
        assertEquals("attachment; filename=\"smime.p7z\"", cbp.getHeader("Content-Disposition")[0]);
        assertEquals("S/MIME Compressed Message", cbp.getHeader("Content-Description")[0]);
    }

    public void testBasic()
        throws Exception
    {
        SMIMECompressedGenerator    cgen = new SMIMECompressedGenerator();
        ByteArrayOutputStream       bOut = new ByteArrayOutputStream();
        MimeBodyPart cbp = cgen.generate(msg, new ZlibCompressor());
        
        SMIMECompressed sc = new SMIMECompressed(cbp);
        
        msg.writeTo(bOut);

        assertTrue(Arrays.areEqual(bOut.toByteArray(), sc.getContent(new ZlibExpanderProvider())));
    }
    
    public void testParser()
        throws Exception
    {
        SMIMECompressedGenerator    cgen = new SMIMECompressedGenerator();
        ByteArrayOutputStream       bOut1 = new ByteArrayOutputStream();
        ByteArrayOutputStream       bOut2 = new ByteArrayOutputStream();
        MimeBodyPart                cbp = cgen.generate(msg, new ZlibCompressor());
        SMIMECompressedParser       sc = new SMIMECompressedParser(cbp);
        
        msg.writeTo(bOut1);
    
        InputStream in = sc.getContent(new ZlibExpanderProvider()).getContentStream();
        int ch;
        
        while ((ch = in.read()) >= 0)
        {
            bOut2.write(ch);
        }
        
        assertTrue(Arrays.areEqual(bOut1.toByteArray(), bOut2.toByteArray()));
    }
    
    /*
     * test compressing and uncompressing of a multipart-signed message.
     */
    public void testCompressedSHA1WithRSA()
        throws Exception
    {
        List           certList = new ArrayList();

        certList.add(origCert);
        certList.add(signCert);

        Store certs = new JcaCertStore(certList);

        ASN1EncodableVector         signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector       caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("SC").setSignedAttributeGenerator(new AttributeTable(signedAttrs)).build("SHA1withRSA", origKP.getPrivate(), origCert));

        gen.addCertificates(certs);

        MimeMultipart smp = gen.generate(msg);

        MimeMessage bp2 = new MimeMessage((Session)null);                          

        bp2.setContent(smp);

        bp2.saveChanges();

        SMIMECompressedGenerator    cgen = new SMIMECompressedGenerator();

        MimeBodyPart cbp = cgen.generate(bp2, new ZlibCompressor());

        SMIMECompressed cm = new SMIMECompressed(cbp);

        MimeMultipart mm = (MimeMultipart)SMIMEUtil.toMimeBodyPart(cm.getContent(new ZlibExpanderProvider())).getContent();
        
        SMIMESigned s = new SMIMESigned(mm);

        ByteArrayOutputStream _baos = new ByteArrayOutputStream();
        msg.writeTo(_baos);
        _baos.close();
        byte[] _msgBytes = _baos.toByteArray();
        _baos = new ByteArrayOutputStream();
        s.getContent().writeTo(_baos);
        _baos.close();
        byte[] _resBytes = _baos.toByteArray();
        
        assertEquals(true, Arrays.areEqual(_msgBytes, _resBytes));

        certs = s.getCertificates();

        SignerInformationStore  signers = s.getSignerInfos();
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getMatches(signer.getSID());

            Iterator            certIt = certCollection.iterator();
            X509CertificateHolder     cert = (X509CertificateHolder)certIt.next();

            assertEquals(true, signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("SC").build(cert)));
        }
    }
}
