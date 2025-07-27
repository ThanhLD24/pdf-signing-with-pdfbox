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
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

public class PdfVisibleSigner2 {

    public static KeyStore generateKeyStore(String alias, char[] password) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        X500Principal dn = new X500Principal("CN=Lee Lee");
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, 1); // Certificate valid for 1 year
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(System.currentTimeMillis()),
                Calendar.getInstance().getTime(), calendar.getTime(), dn, keyPair.getPublic())
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
            // Lấy trang đầu tiên (index 0)
            PDPage page = doc.getPage(0);

            // In kích thước trang để debug
            PDRectangle mediaBox = page.getMediaBox();
            System.out.println("Page size: " + mediaBox.getWidth() + " x " + mediaBox.getHeight());

            // Tạo chữ ký số
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName("Lee Lee");
            signature.setReason("Signed with visible image");
            signature.setSignDate(Calendar.getInstance());

            // Thiết lập AcroForm
            PDAcroForm acroForm = doc.getDocumentCatalog().getAcroForm();
            if (acroForm == null) {
                acroForm = new PDAcroForm(doc);
                doc.getDocumentCatalog().setAcroForm(acroForm);
            }
            acroForm.setSignaturesExist(true);
            acroForm.setNeedAppearances(true);

            // Tạo trường chữ ký
            PDSignatureField sigField = new PDSignatureField(acroForm);
            sigField.setPartialName("Signature" + System.currentTimeMillis());

            // Tạo widget annotation
            PDAnnotationWidget widget = new PDAnnotationWidget();
            PDRectangle rect = new PDRectangle(x, y, width, height);
            widget.setRectangle(rect);
            widget.setPage(page);
            widget.setPrinted(true);

            // Thêm widget vào trang và trường chữ ký
            page.getAnnotations().add(widget);
            sigField.getWidgets().add(widget);
            acroForm.getFields().add(sigField);
            sigField.setValue(signature);

            // Tạo appearance cho hình ảnh chữ ký
            BufferedImage img = ImageIO.read(signatureImage);
            PDImageXObject pdImage = PDImageXObject.createFromByteArray(doc, imageToBytes(img), "signature");

            PDAppearanceStream appearanceStream = new PDAppearanceStream(doc);
            appearanceStream.setBBox(new PDRectangle(width, height));
            PDResources resources = new PDResources();
            resources.put(COSName.getPDFName("Im0"), pdImage);
            appearanceStream.setResources(resources);

            // Tạo nội dung appearance stream
            try (OutputStream os = appearanceStream.getCOSObject().createOutputStream(COSName.FLATE_DECODE)) {
                String cmd = String.format("q %f 0 0 %f 0 0 cm /Im0 Do Q", width, height);
                os.write(cmd.getBytes("UTF-8"));
            }

            // Gán appearance cho widget
            PDAppearanceDictionary appearanceDict = new PDAppearanceDictionary();
            appearanceDict.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearanceDict);

            // Ký số với chứng chỉ
            SignatureInterface signatureInterface = content -> {
                try {
                    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                    JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(
                            new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build());
                    gen.addSignerInfoGenerator(builder.build(
                            new JcaContentSignerBuilder("SHA256withRSA").build(privateKey),
                            new JcaX509CertificateHolder(cert)));
                    gen.addCertificate(new JcaX509CertificateHolder(cert));
                    CMSProcessableByteArray contentBytes = new CMSProcessableByteArray(content.readAllBytes());
                    CMSSignedData signedData = gen.generate(contentBytes, true);
                    return signedData.getEncoded();
                } catch (Exception e) {
                    throw new IOException("Error signing content", e);
                }
            };

            // Thêm chữ ký vào tài liệu
            SignatureOptions options = new SignatureOptions();
            options.setPreferredSignatureSize(3276800); // Tăng kích thước dự phòng
            doc.addSignature(signature, signatureInterface, options);

            // Lưu tài liệu
            try (FileOutputStream fos = new FileOutputStream(outputPdf)) {
                doc.saveIncremental(fos);
            } catch (Exception e) {
                System.err.println("Error saving PDF: " + e.getMessage());
                e.printStackTrace();
                throw e;
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
        File output = new File("signed_visible_6.pdf");
        File img = new File("signature.png");
        String alias = "self";
        char[] pwd = "123456".toCharArray();
        KeyStore ks = generateKeyStore(alias, pwd);

        // Ký với tọa độ và kích thước hợp lý
        signWithVisibleImage(input, output, img, 50, 50, 200, 100, ks, alias, pwd);
        System.out.println("Signed with visible signature!");
    }
}