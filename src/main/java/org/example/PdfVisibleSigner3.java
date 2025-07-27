package org.example;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.cos.COSName;

import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.awt.geom.Rectangle2D;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.math.BigInteger;
import javax.security.auth.x500.X500Principal;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDFTemplateCreator;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

public class PdfVisibleSigner3 {

    public static KeyStore createKeyStore(char[] pwd) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();
        X500Principal dn = new X500Principal("CN=Test");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        X509CertificateHolder h = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(System.currentTimeMillis()),
                Calendar.getInstance().getTime(), Calendar.getInstance().getTime(),
                dn, kp.getPublic()).build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(h);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, pwd);
        ks.setKeyEntry("alias", kp.getPrivate(), pwd, new java.security.cert.Certificate[]{cert});
        return ks;
    }

    public static void signPDFVisible(
            File in, File out, File imageFile,
            Rectangle2D humanRect, KeyStore ks, char[] pwd
    ) throws Exception {
        PrivateKey priv = (PrivateKey) ks.getKey("alias", pwd);
        X509Certificate cert = (X509Certificate) ks.getCertificate("alias");

        try (PDDocument doc = Loader.loadPDF(in)) {
            PDAcroForm form = doc.getDocumentCatalog().getAcroForm();
            if (form == null) {
                form = new PDAcroForm(doc);
                doc.getDocumentCatalog().setAcroForm(form);
            }
            SignatureOptions options = new SignatureOptions();
            // chuyển tọa độ "nhân đạo" (từ trên-góc trái) sang PDF (từ dưới-góc trái)
            PDPage page = doc.getPage(0);
            float pageH = page.getMediaBox().getHeight();
            PDRectangle rect = new PDRectangle(
                    (float)humanRect.getX(),
                    pageH - (float)humanRect.getY() - (float)humanRect.getHeight(),
                    (float)humanRect.getWidth(),
                    (float)humanRect.getHeight()
            );



            options.setPage(0);
            options.setVisualSignature(createVisualAppearance(doc, rect, imageFile));
            options.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE);

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Signer");
            signature.setLocation("VN");
            signature.setReason("Visible signing");
            signature.setSignDate(Calendar.getInstance());

            SignatureInterface si = content -> {
                try {
                    Signature s = Signature.getInstance("SHA256withRSA");
                    s.initSign(priv);
                    byte[] buf = new byte[8192];
                    int r;
                    while ((r = content.read(buf)) != -1) {
                        s.update(buf, 0, r);
                    }
                    return s.sign();
                }
                catch (Exception e) {
                    throw new IOException("Error reading content stream", e);
                }

            };

            doc.addSignature(signature, si, options);
            try (FileOutputStream fos = new FileOutputStream(out)) {
                doc.saveIncremental(fos);
            }
            options.close();
        }
    }

    private static InputStream createVisualAppearance(PDDocument doc, PDRectangle rect, File imgFile) throws IOException {
        BufferedImage img = ImageIO.read(imgFile);
        PDImageXObject pdImg = PDImageXObject.createFromByteArray(doc, toBytes(img), "sig");

        PDAppearanceStream stream = new PDAppearanceStream(doc);
        stream.setResources(new PDResources());
        stream.setBBox(new PDRectangle(rect.getWidth(), rect.getHeight()));

        try (OutputStream os = stream.getContentStream().createOutputStream()) {
            String cmd = String.format("q %f 0 0 %f 0 0 cm /Im0 Do Q",
                    rect.getWidth(), rect.getHeight());
            os.write(cmd.getBytes("UTF-8"));
        }
        stream.getResources().put(COSName.getPDFName("Im0"), pdImg);

        PDAppearanceDictionary dict = new PDAppearanceDictionary();
        dict.setNormalAppearance(stream);

        // Convert to InputStream for SignatureOptions
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        doc.save(baos);
        return new ByteArrayInputStream(baos.toByteArray());
    }

    private static byte[] toBytes(BufferedImage img) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", baos);
        return baos.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        KeyStore ks = createKeyStore("pwd".toCharArray());
        signPDFVisible(new File("input.pdf"), new File("signed_visible_7.pdf"),
                new File("signature.png"),
                new Rectangle2D.Float(100, 100, 150, 50),
                ks, "pwd".toCharArray());
        System.out.println("Signed visible done!");
    }
}
