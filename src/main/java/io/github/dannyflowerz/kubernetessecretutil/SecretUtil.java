package io.github.dannyflowerz.kubernetessecretutil;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;


public final class SecretUtil {

    private SecretUtil() {}

    /**
     * Loads a Kubernetes secret containing a key and a certificate as a key pair into a JKS key store
     *
     * @param mountPath the path where the secret is mounted
     * @param keyFileName name of the key in the secret
     * @param certificateFileName name of the certificate in the secret
     * @param keyAlias desired alias for the key pair in the key store
     * @param keyPassword desired password for the key pair in the key store
     * @return the initialized key store
     */
    public static KeyStore loadK8sSecretAsKeyStore(String mountPath, String keyFileName, String certificateFileName, String keyAlias, String keyPassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            loadKeyPairIntoKeyStore(mountPath, keyFileName, certificateFileName, keyAlias, keyPassword, keyStore);
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | InvalidKeySpecException e) {
            throw new KeyStoreInitializationException("Unable to initialize JKS key store from Kubernetes secrets " + keyFileName + " and " + certificateFileName, e);
        }
    }

    /**
     * Loads a Kubernetes secret containing a certificate chain as individual trusted certificates into a JKS key store
     *
     * @param mountPath the path where the secret is mounted
     * @param certificateChainFileName name of the certificate chain in the secret
     * @return the initialized key store
     */
    public static KeyStore loadK8sSecretAsTrustStore(String mountPath, String certificateChainFileName) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            loadCertificatesIntoTrustStore(mountPath, certificateChainFileName, keyStore);
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreInitializationException("Unable to initialize JKS trust store from Kubernetes secret " + certificateChainFileName, e);
        }
    }

    /**
     * Loads a Kubernetes secret containing a key and a certificate as a key pair,
     * and a Kubernetes secret containing a certificate chain as individual trusted certificates
     * into a combined JKS key- and trust store
     *
     * @param mountPath the path where the secret is mounted
     * @param keyFileName name of the key in the secret
     * @param certificateFileName name of the certificate in the secret
     * @param keyAlias desired alias for the key pair in the key store
     * @param keyPassword desired password for the key pair in the key store
     * @param certificateChainFileName name of the certificate chain in the secret
     * @return the initialized key store
     */
    public static KeyStore loadK8sSecretAsKeyAndTrustStore(String mountPath, String keyFileName, String certificateFileName, String keyAlias, String keyPassword, String certificateChainFileName) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            loadKeyPairIntoKeyStore(mountPath, keyFileName, certificateFileName, keyAlias, keyPassword, keyStore);
            loadCertificatesIntoTrustStore(mountPath, certificateChainFileName, keyStore);
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | InvalidKeySpecException e) {
            throw new KeyStoreInitializationException("Unable to initialize JKS key- and trust store from Kubernetes secrets " + keyFileName + ", " + certificateFileName + " and " + certificateChainFileName, e);
        }
    }

    private static void loadKeyPairIntoKeyStore(String mountPath, String keyFileName, String certificateFileName, String keyAlias, String keyPassword, KeyStore keyStore)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, KeyStoreException {
        Security.addProvider(new BouncyCastleProvider());
        String pemKey = new String(Files.readAllBytes(Paths.get(mountPath, keyFileName)), Charset.defaultCharset());
        pemKey = pemKey.replaceAll("\\s", "");
        pemKey = pemKey.replace("-----BEGINRSAPRIVATEKEY-----", "");
        pemKey = pemKey.replace("-----ENDRSAPRIVATEKEY-----", "");
        byte[] derKey = Base64.decode(pemKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(derKey));

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certCollection = certificateFactory.generateCertificates(Files.newInputStream(Paths.get(mountPath, certificateFileName)));
        Certificate[] certificates = new Certificate[certCollection.size()];

        KeyStore.PrivateKeyEntry keyEntry = new KeyStore.PrivateKeyEntry(privateKey, certCollection.toArray(certificates));
        keyStore.setEntry(keyAlias, keyEntry, new KeyStore.PasswordProtection(keyPassword.toCharArray()));
    }

    private static void loadCertificatesIntoTrustStore(String mountPath, String certificateChainFileName, KeyStore keyStore)
            throws CertificateException, IOException, KeyStoreException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certCollection = certificateFactory.generateCertificates(Files.newInputStream(Paths.get(mountPath, certificateChainFileName)));

        for (Certificate cert : certCollection) {
            keyStore.setCertificateEntry(((X509Certificate) cert).getSubjectDN().getName().split(",")[0].trim(), cert);
        }
    }

}
