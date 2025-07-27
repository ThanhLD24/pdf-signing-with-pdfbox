package org.example;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.PDPage;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.imageio.ImageIO;
import javax.security.auth.x500.X500Principal;
import java.awt.image.BufferedImage;
import java.security.cert.Certificate;

public class PdfBoxSigner {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Bước 1: Tạo cặp khóa và chứng chỉ self-signed
    public static KeyStore generateSelfSignedCertificate(String alias, char[] password) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        long now = System.currentTimeMillis();
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(now);

        X500Principal dnName = new X500Principal("CN=Test, O=MyOrg");
        X509Certificate cert;

        // Tạo self-signed certificate
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = new JcaX509v3CertificateBuilder(
                dnName, BigInteger.valueOf(now), calendar.getTime(),
                calendar.getTime(), dnName, keyPair.getPublic())
                .build(sigGen);
        cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);

        // Tạo KeyStore chứa key + cert
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);
        ks.setKeyEntry(alias, keyPair.getPrivate(), password, new Certificate[]{cert});
        return ks;
    }

    // Bước 2: Ký file PDF với hình ảnh chữ ký
    public static void signPDF(
            File inputPdf,
            File outputPdf,
            File imageFile,
            float x, float y, float width, float height,
            KeyStore keyStore,
            String alias,
            char[] password
    ) throws Exception {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        Certificate[] chain = keyStore.getCertificateChain(alias);

        PDDocument document = Loader.loadPDF(inputPdf);
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("Lee Lee");
        signature.setLocation("Vietnam");
        signature.setReason("Testing visible signature");
        signature.setSignDate(Calendar.getInstance());

        // Add signature field to document
        PDRectangle rect = new PDRectangle(x, y, width, height);
        PDPage page = document.getPage(0);

        BufferedImage image = ImageIO.read(imageFile);
        PDVisibleSignDesigner visibleSignDesigner = new PDVisibleSignDesigner(document, image, 1);
        visibleSignDesigner.xAxis(x).yAxis(y).width(width).height(height);

        PDVisibleSigProperties visibleSigProps = new PDVisibleSigProperties();
        visibleSigProps
                .visualSignEnabled(true)
                .setPdVisibleSignature(visibleSignDesigner).page(1)
                .buildSignature();

        SignatureInterface signatureInterface = new SignatureInterface() {
            @Override
            public byte[] sign(InputStream content) throws IOException {
                try {
                    Signature sig = Signature.getInstance("SHA256withRSA");
                    sig.initSign(privateKey);
                    byte[] buffer = new byte[8192];
                    int c;
                    while ((c = content.read(buffer)) != -1) {
                        sig.update(buffer, 0, c);
                    }
                    return sig.sign();
                } catch (Exception e) {
                    throw new IOException("Ký thất bại", e);
                }
            }
        };
        document.addSignature(signature, signatureInterface);
        document.saveIncremental(new FileOutputStream(outputPdf));

        document.close();
    }

    public static void main(String[] args) throws Exception {
        File inputPdf = new File("input.pdf");
        File outputPdf = new File("signed-output.pdf");
        File signatureImage = new File("signature.png");

        String alias = "test";
        char[] password = "password".toCharArray();

        KeyStore ks = generateSelfSignedCertificate(alias, password);

        // Giả sử vị trí chữ ký ở góc dưới bên phải (tọa độ tính theo point 72 = 1 inch)
        signPDF(
                inputPdf,
                outputPdf,
                signatureImage,
                400, 100, 150, 50, // x, y, width, height
                ks,
                alias,
                password
        );
        System.out.println("Ký PDF thành công!");
    }
}
