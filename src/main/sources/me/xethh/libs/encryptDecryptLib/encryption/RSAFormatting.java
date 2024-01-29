package me.xethh.libs.encryptDecryptLib.encryption;

import lombok.SneakyThrows;
import lombok.val;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAFormatting {
    public static byte[] toX509(byte[] bytes){
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
            PublicKey rsaPublicKey = kf.generatePublic(spec);
            return rsaPublicKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    public static byte[] toPKCS1PrivateKey(PrivateKey privateKey){
        try {
            PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
            ASN1Encodable privateKeyPKCS1ASN1Encodable = null;
            privateKeyPKCS1ASN1Encodable = pkInfo.parsePrivateKey();
            ASN1Primitive privateKeyPKCS1ASN1 = privateKeyPKCS1ASN1Encodable.toASN1Primitive();
            return privateKeyPKCS1ASN1.getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    public static byte[] toPKCS1PublicKey(PublicKey publicKey){
        try {
            SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            ASN1Primitive publicKeyPKCS1ASN1Encodable = pkInfo.parsePublicKey();
            ASN1Primitive publicKeyPKCS1ASN1 = publicKeyPKCS1ASN1Encodable.toASN1Primitive();
            return publicKeyPKCS1ASN1.getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    public static void toPKCS12(String keyStorePwd, String keyStoreFile,
                                PrivateKey privateKey, X509Certificate certificate){
        try {
            char[] pwd = keyStorePwd.toCharArray();

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, pwd);

            KeyStore.ProtectionParameter protParam =
                    new KeyStore.PasswordProtection(pwd);
            Certificate[] certChain =
                    new Certificate[]{ certificate };
            KeyStore.PrivateKeyEntry pkEntry =
                    new KeyStore.PrivateKeyEntry(privateKey, certChain);
            ks.setEntry("keypair", pkEntry, protParam);
            FileOutputStream fos = new FileOutputStream(keyStoreFile);
            ks.store(fos, pwd);
            fos.close();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
        }

    }

    private enum PemHeaderPosition {
        Begin("BEGIN"), End("END");
        private String code;

        PemHeaderPosition(String code) {
            this.code = code;
        }
    }

    private static String pemHeader(PemHeaderPosition position, String tagName) {
        return String.format("-----%s %s-----", position.code.toUpperCase(), tagName);
    }

    private static String splitPem(String data) {
        val splitSize = 50;
        val row = (data.length() / splitSize) + (data.length() % splitSize == 0 ? 0 : 1);
        val sb = new StringBuilder();
        for (int i = 0; i < row; i++) {
            sb.append(data.substring(i * splitSize, Math.min(i * splitSize + splitSize, data.length())));
            if (i + 1 < row)
                sb.append("\n");
        }
        return sb.toString();
    }

    /**
     * The key stored as PKCS#8
     * @param privateKey private key
     * @return private key as pem string
     */
    public static String toPem(PrivateKey privateKey){
        PKCS8EncodedKeySpec sp = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        return pemHeader(PemHeaderPosition.Begin, "PRIVATE KEY") + "\n" +
                splitPem(Base64.getEncoder().encodeToString(sp.getEncoded())) +
                "\n" + pemHeader(PemHeaderPosition.End, "PRIVATE KEY") + "\n";
    }
    public static String toPemPKCS1(Key key){
        if(key instanceof PrivateKey){
            return pemHeader(PemHeaderPosition.Begin, "RSA PRIVATE KEY")+"\n" +
                    splitPem(Base64.getEncoder().encodeToString(toPKCS1PrivateKey((PrivateKey) key))) +
                    String.format("\n%s\n", pemHeader(PemHeaderPosition.End, "RSA PRIVATE KEY"));
        }
        else{
            return String.format("%s\n", pemHeader(PemHeaderPosition.Begin, "RSA PUBLIC KEY")) +
                    splitPem(Base64.getEncoder().encodeToString(toPKCS1PublicKey((PublicKey) key))) +
                    String.format("\n%s\n", pemHeader(PemHeaderPosition.End, "RSA PUBLIC KEY"));
        }
    }
    public static String toPem(PublicKey publicKey){
        PKCS8EncodedKeySpec sp = new PKCS8EncodedKeySpec(publicKey.getEncoded());
        SubjectPublicKeyInfo pkcs1 = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        //System.out.println(publicKey.getAlgorithm());
        //System.out.println(publicKey.getFormat());
        //System.out.println(sp.getFormat());
        //System.out.println(pkcs1.getAlgorithm().getAlgorithm());

        return String.format("%s\n", pemHeader(PemHeaderPosition.Begin, "PUBLIC KEY")) +
                splitPem(Base64.getEncoder().encodeToString(publicKey.getEncoded())) +
                String.format("\n%s\n", pemHeader(PemHeaderPosition.End, "PUBLIC KEY"));
    }

    @SneakyThrows
    protected static byte[] loadPemBytes(String name) {
        val pattern = Pattern.compile("-----(BEGIN|END) ([ \\w]+)-----");
        val bytes = Files.readAllBytes(new File(name).toPath());
        return Base64.getDecoder().decode(
                Arrays.stream(new String(bytes, UTF_8).split("\n"))
                        .filter(it -> !pattern.matcher(it).matches())
                        .collect(Collectors.joining(""))
                        .getBytes(UTF_8)
        );
    }


    public static void main(String[] args){
        KeyPair pair = RsaEncryption.keyPair();
        FileOutputStream fos = null;
        try {

            fos = new FileOutputStream("message.encrypted");
            fos.write(Base64.getDecoder().decode(RsaEncryption.encrypt("hi",pair.getPublic()).getBytes()));
            fos.flush();
            fos.close();

            fos = new FileOutputStream("private.pkcs1.pem");
            fos.write(toPemPKCS1(pair.getPrivate()).getBytes());
            fos.flush();
            fos.close();
            fos = new FileOutputStream("private.pem");
            fos.write(toPem(pair.getPrivate()).getBytes());
            fos.flush();
            fos.close();
            val privateKey = RsaEncryption.getPrivateKeyFromPem("private.pem");
            fos = new FileOutputStream("public.pkcs1.pem");
            fos.write(toPemPKCS1(pair.getPublic()).getBytes());
            fos.flush();
            fos.close();
            fos = new FileOutputStream("public.pem");
            fos.write(toPem(pair.getPublic()).getBytes());
            fos.flush();
            fos.close();
            val publicKey = RsaEncryption.getPubKeyFromPem("public.pem");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
