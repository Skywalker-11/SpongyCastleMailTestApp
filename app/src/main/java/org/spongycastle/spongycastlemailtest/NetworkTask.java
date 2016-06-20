package org.spongycastle.spongycastlemailtest;

import android.os.AsyncTask;
import android.support.design.widget.Snackbar;
import android.util.Log;
import android.view.View;

import com.sun.mail.smtp.SMTPTransport;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.cms.AttributeTable;
import org.spongycastle.asn1.cms.IssuerAndSerialNumber;
import org.spongycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.spongycastle.asn1.smime.SMIMECapability;
import org.spongycastle.asn1.smime.SMIMECapabilityVector;
import org.spongycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.AuthorityKeyIdentifier;
import org.spongycastle.asn1.x509.SubjectKeyIdentifier;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.bc.BcX509ExtensionUtils;
import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.cms.CMSAlgorithm;
import org.spongycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.spongycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.spongycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.spongycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.spongycastle.mail.smime.SMIMESignedGenerator;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.util.Store;
import org.spongycastle.util.Strings;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

/**
 * @author Skywalker-11
 * see org.spongycastle.mail.smime.examples.CreateSignedMail.java, org.spongycastle.mail.smime.examples.SendSignedAndEncryptedMail.java
 */
public class NetworkTask extends AsyncTask {
    View view;

    public NetworkTask(View view) {
        this.view = view;
    }

    @Override
    protected Object doInBackground(Object[] objects) {
        String recipientString = "recipient@example.org";
        String senderString = "sender@example.org";
        String serverString = "example.org";
        String userString = "sender@example.org";
        String passwordString = "<userpassword_here>";
        int port = 25;

        Properties props = System.getProperties();
        props.put("mail.smtp.host", serverString);
        props.put("mail.smtp.auth", true);
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", true);
        Session session = Session.getInstance(props);


        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", "SC");
            kpg.initialize(1024, new SecureRandom());

            //
            // cert that issued the signing certificate
            //
            String signDN = "O=Bouncy Castle, C=AU";
            KeyPair signKP = kpg.generateKeyPair();
            X509Certificate signCert = makeCertificate(
                    signKP, signDN, signKP, signDN);

            //
            // cert we sign against
            //
            String origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
            KeyPair origKP = kpg.generateKeyPair();
            X509Certificate origCert = makeCertificate(
                    origKP, origDN, signKP, signDN);

            List certList = new ArrayList();

            certList.add(origCert);
            certList.add(signCert);
            PrivateKey privateKey = origKP.getPrivate();
            if (privateKey == null) {
                throw new Exception("cannot find private key");
            }

            /* Create the message to sign and encrypt */

            MimeMessage body = new MimeMessage(session);
            body.setFrom(new InternetAddress(senderString));
            body.setRecipient(Message.RecipientType.TO, new InternetAddress(
                    recipientString));
            body.setSubject("example encrypted message");
            body.setContent("example encrypted message", "text/plain");
            body.saveChanges();

            /* Create the SMIMESignedGenerator */
            SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
            capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
            capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
            capabilities.addCapability(SMIMECapability.dES_CBC);

            ASN1EncodableVector attributes = new ASN1EncodableVector();
            attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(
                    new IssuerAndSerialNumber(
                            new X500Name(origCert.getIssuerDN().getName()),
                            origCert.getSerialNumber())));
            attributes.add(new SMIMECapabilitiesAttribute(capabilities));

            SMIMESignedGenerator signer = new SMIMESignedGenerator();
            signer.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("SC").setSignedAttributeGenerator(new AttributeTable(attributes)).build("DSA".equals(privateKey.getAlgorithm()) ? "SHA1withDSA" : "MD5withRSA", privateKey, origCert));

            Store certs = new JcaCertStore(certList);
            signer.addCertificates(certs);

            /* Sign the message */
            MimeMultipart mm = signer.generate(body);
            MimeMessage signedMessage = new MimeMessage(session);

            /* Set all original MIME headers in the signed message */
            Enumeration headers = body.getAllHeaderLines();
            while (headers.hasMoreElements()) {
                signedMessage.addHeaderLine((String) headers.nextElement());
            }

            /* Set the content of the signed message */
            signedMessage.setContent(mm);
            signedMessage.saveChanges();

            /* Create the encrypter */
            SMIMEEnvelopedGenerator encrypter = new SMIMEEnvelopedGenerator();
            encrypter.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(origCert).setProvider("SC"));

            /* Encrypt the message */
            MimeBodyPart encryptedPart = encrypter.generate(signedMessage,
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.RC2_CBC).setProvider("SC").build());

            /*
             * Create a new MimeMessage that contains the encrypted and signed
             * content
             */
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            encryptedPart.writeTo(out);

            MimeMessage encryptedMessage = new MimeMessage(session,
                    new ByteArrayInputStream(out.toByteArray()));

            /* Set all original MIME headers in the encrypted message */
            headers = body.getAllHeaderLines();
            while (headers.hasMoreElements()) {
                String headerLine = (String) headers.nextElement();
                /*
                 * Make sure not to override any content-* headers from the
                 * original message
                 */
                if (!Strings.toLowerCase(headerLine).startsWith("content-")) {
                    encryptedMessage.addHeaderLine(headerLine);
                }
            }
            SMTPTransport t = (SMTPTransport) session.getTransport("smtp");
            t.connect(serverString, port, userString, passwordString);
            t.sendMessage(encryptedMessage, encryptedMessage.getAllRecipients());

            Snackbar.make(view,
                    t.getLastServerResponse(), Snackbar.LENGTH_LONG)
                    .setAction("Action", null).show();
            Log.i("INFO", t.getLastServerResponse());

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    static int serialNo = 1;

    static AuthorityKeyIdentifier createAuthorityKeyId(
            PublicKey pub)
            throws IOException {
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(pub.getEncoded());

        return new AuthorityKeyIdentifier(info);
    }

    static SubjectKeyIdentifier createSubjectKeyId(
            PublicKey pub)
            throws IOException {
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(pub.getEncoded());

        return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
    }

    /**
     * create a basic X509 certificate from the given keys
     */
    static X509Certificate makeCertificate(
            KeyPair subKP,
            String subDN,
            KeyPair issKP,
            String issDN)
            throws GeneralSecurityException, IOException, OperatorCreationException {
        PublicKey subPub = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey issPub = issKP.getPublic();

        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(new X500Name(issDN), BigInteger.valueOf(serialNo++), new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), new X500Name(subDN), subPub);

        v3CertGen.addExtension(
                X509Extension.subjectKeyIdentifier,
                false,
                createSubjectKeyId(subPub));

        v3CertGen.addExtension(
                X509Extension.authorityKeyIdentifier,
                false,
                createAuthorityKeyId(issPub));

        return new JcaX509CertificateConverter().setProvider("SC").getCertificate(v3CertGen.build(new JcaContentSignerBuilder("MD5withRSA").setProvider("SC").build(issPriv)));
    }

}
