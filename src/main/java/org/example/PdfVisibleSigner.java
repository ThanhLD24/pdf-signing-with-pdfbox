package org.example;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.apache.pdfbox.pdmodel.interactive.form.*;
import org.apache.pdfbox.pdmodel.interactive.annotation.*;

import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;

import java.awt.image.BufferedImage;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import javax.imageio.ImageIO;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

public class PdfVisibleSigner {

    public static KeyStore generateKeyStore(String alias, char[] password) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        X500Principal dn = new X500Principal("CN=Lee Lee");
        Calendar calendar = Calendar.getInstance();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(System.currentTimeMillis()),
                calendar.getTime(), calendar.getTime(), dn, keyPair.getPublic())
                .build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);
        ks.setKeyEntry(alias, keyPair.getPrivate(), password, new java.security.cert.Certificate[]{cert});
        return ks;
    }

    public static void signWithVisibleImage(
            File inputPdf, File outputPdf, File signatureImage,
            float x, float y, float width, float height,
            KeyStore keyStore, String alias, char[] password) throws Exception {

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        try (PDDocument doc = Loader.loadPDF(inputPdf)) {
            PDPage page = doc.getPage(1);

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Lee Lee");
            signature.setReason("Signed with visible image");
            signature.setSignDate(Calendar.getInstance());

            PDAcroForm acroForm = doc.getDocumentCatalog().getAcroForm();
            if (acroForm == null) {
                acroForm = new PDAcroForm(doc);
                doc.getDocumentCatalog().setAcroForm(acroForm);
            }

            // Tạo trường chữ ký và widget
            PDSignatureField sigField = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = sigField.getWidgets().get(0);
            PDRectangle rect = new PDRectangle(x, y, width, height);
            widget.setRectangle(rect);
            widget.setPage(page);
            page.getAnnotations().add(widget);

            acroForm.getFields().add(sigField);
            sigField.setValue(signature);

            // Chèn ảnh vào appearance
            BufferedImage img = ImageIO.read(signatureImage);
            PDImageXObject pdImage = PDImageXObject.createFromByteArray(doc, imageToBytes(img), "sign");

            PDAppearanceStream appearanceStream = new PDAppearanceStream(doc);
            appearanceStream.setResources(new PDResources());
            appearanceStream.setBBox(new PDRectangle(width, height));

            try (OutputStream os = appearanceStream.getContentStream().createOutputStream()) {
                String cmd = String.format("q %f 0 0 %f 0 0 cm /Im0 Do Q", width, height);
                os.write(cmd.getBytes("UTF-8"));
            }
            appearanceStream.getResources().put(COSName.getPDFName("Im0"), pdImage);

            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);

            // Ký số
            SignatureInterface signatureInterface = content -> {
                try {
                    Signature sig = Signature.getInstance("SHA256withRSA");
                        sig.initSign(privateKey);

                    byte[] buffer = new byte[8192];
                    int n;
                    while ((n = content.read(buffer)) > 0) {
                        sig.update(buffer, 0, n);
                    }
                    return sig.sign();
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                catch (NoSuchAlgorithmException | SignatureException e) {
                    throw new IOException("Error signing content", e);
                }
            };

            doc.addSignature(signature, signatureInterface);
            try (FileOutputStream fos = new FileOutputStream(outputPdf)) {
                doc.saveIncremental(fos);
            }
        }
    }

    private static byte[] imageToBytes(BufferedImage img) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", baos);
        return baos.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        File input = new File("input.pdf");
        File output = new File("signed_visible_2.pdf");
        File img = new File("signature.png");
        String alias = "self";
        char[] pwd = "123456".toCharArray();
        KeyStore ks = generateKeyStore(alias, pwd);

        signWithVisibleImage(input, output, img, 100, 100, 150, 50, ks, alias, pwd);
        System.out.println("Signed with visible signature!");
    }
}
