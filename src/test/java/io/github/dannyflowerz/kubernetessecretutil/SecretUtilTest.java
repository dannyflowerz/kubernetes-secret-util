package io.github.dannyflowerz.kubernetessecretutil;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateCrtKey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SecretUtilTest {

    @Test
    @DisplayName("SHOULD load secrets into key store")
    void loadK8sSecretAsKeyStoreHappy() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        // given
        String mountPath = Paths.get(this.getClass().getResource("/tls.key").getPath()).getParent().toString();

        // when
        KeyStore keyStore = SecretUtil.loadK8sSecretAsKeyStore(mountPath, "tls.key", "tls.crt", "alias", "password");

        // then
        assertTrue(keyStore.getKey("alias", "password".toCharArray()) instanceof RSAPrivateCrtKey);
    }

    @Test
    @DisplayName("SHOULD throw KeyStoreInitializationException WHEN key is not found")
    void loadK8sSecretAsKeyStoreUnhappy() {
        // given
        String mountPath = Paths.get(this.getClass().getResource("/tls.key").getPath()).getParent().toString();

        // when - then
        assertThrows(KeyStoreInitializationException.class, () -> SecretUtil.loadK8sSecretAsKeyStore(mountPath, "nope.key", "tls.crt", "alias", "password"));
    }

    @Test
    @DisplayName("SHOULD load secret into trust store")
    void loadK8sSecretAsTrustStoreHappy() throws CertificateException, KeyStoreException {
        // given
        String mountPath = Paths.get(this.getClass().getResource("/ca.crt").getPath()).getParent().toString();
        String certText = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDzzCCAregAwIBAgIQTAKF/mTTiunPDZ51KWg/EzANBgkqhkiG9w0BAQsFADBU\n" +
                "MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMSUw\n" +
                "IwYDVQQDExxHb29nbGUgSW50ZXJuZXQgQXV0aG9yaXR5IEczMB4XDTE5MDcyOTE4\n" +
                "NDMyMloXDTE5MTAyMTE4MjMwMFowaDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh\n" +
                "bGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2ds\n" +
                "ZSBMTEMxFzAVBgNVBAMMDnd3dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZI\n" +
                "zj0DAQcDQgAELPYz+3+RbnpY3vzgq9yIVbLMDs0a4dZvPff4Q2qWkjqjscxL9bqx\n" +
                "IfmqvVAeyZdFKKN4u5Dlq/7mWLQfvEtcU6OCAVIwggFOMBMGA1UdJQQMMAoGCCsG\n" +
                "AQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNv\n" +
                "bTBoBggrBgEFBQcBAQRcMFowLQYIKwYBBQUHMAKGIWh0dHA6Ly9wa2kuZ29vZy9n\n" +
                "c3IyL0dUU0dJQUczLmNydDApBggrBgEFBQcwAYYdaHR0cDovL29jc3AucGtpLmdv\n" +
                "b2cvR1RTR0lBRzMwHQYDVR0OBBYEFFJ56Q1CziCuxAyVY90CV7BMrgFDMAwGA1Ud\n" +
                "EwEB/wQCMAAwHwYDVR0jBBgwFoAUd8K4UJpndnaxLcKG0IOgfqZ+ukswIQYDVR0g\n" +
                "BBowGDAMBgorBgEEAdZ5AgUDMAgGBmeBDAECAjAxBgNVHR8EKjAoMCagJKAihiBo\n" +
                "dHRwOi8vY3JsLnBraS5nb29nL0dUU0dJQUczLmNybDANBgkqhkiG9w0BAQsFAAOC\n" +
                "AQEAqwctkMxmgivcpNL0VTvFi8aIdSF6M9TBqW1es7EbmzhoS/N8YCZwgX55naUd\n" +
                "riVE/SvM1S2UCw1ErF35Bp2qfIN7/e14oepcfAwQc9ryZFJGwNr6k4tTgKrJT12t\n" +
                "T8QFvy1MmX0993DZP550t7qu0xtaymrQn8356paUmkblhJLanHS4AY84cMI/WWfT\n" +
                "vv5J3Os/m3uwZGrcro3HiUIBDZNrPRm9gYtx4WhmJ4FfPtkWGtjvaJPWyKmLZZA5\n" +
                "OZfTbgOfuSfijWgbsOdu/A9cz2VufJGyqS2zPTtA0nLeBz8358sdkpAP7TC2VIP9\n" +
                "AWBQx3SbgohiAde4zLqtz/NJfQ==\n" +
                "-----END CERTIFICATE-----";
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certText.getBytes()));

        // when
        KeyStore keyStore = SecretUtil.loadK8sSecretAsTrustStore(mountPath, "ca.crt");

        // then
        assertEquals("cn=www.google.com", keyStore.getCertificateAlias(certificate));
    }

    @Test
    @DisplayName("SHOULD throw KeyStoreInitializationException WHEN certificate chain is not found")
    void loadK8sSecretAsTrustStoreUnappy() {
        // given
        String mountPath = Paths.get(this.getClass().getResource("/ca.crt").getPath()).getParent().toString();

        // when - then
        assertThrows(KeyStoreInitializationException.class, () -> SecretUtil.loadK8sSecretAsTrustStore(mountPath, "nope.crt"));
    }

    @Test
    @DisplayName("SHOULD load secrets into combined key- and trust store")
    void loadK8sSecretAsKeyAndTrustStoreHappy() throws CertificateException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        // given
        String mountPath = Paths.get(this.getClass().getResource("/ca.crt").getPath()).getParent().toString();
        String certText = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDzzCCAregAwIBAgIQTAKF/mTTiunPDZ51KWg/EzANBgkqhkiG9w0BAQsFADBU\n" +
                "MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMSUw\n" +
                "IwYDVQQDExxHb29nbGUgSW50ZXJuZXQgQXV0aG9yaXR5IEczMB4XDTE5MDcyOTE4\n" +
                "NDMyMloXDTE5MTAyMTE4MjMwMFowaDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh\n" +
                "bGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2ds\n" +
                "ZSBMTEMxFzAVBgNVBAMMDnd3dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZI\n" +
                "zj0DAQcDQgAELPYz+3+RbnpY3vzgq9yIVbLMDs0a4dZvPff4Q2qWkjqjscxL9bqx\n" +
                "IfmqvVAeyZdFKKN4u5Dlq/7mWLQfvEtcU6OCAVIwggFOMBMGA1UdJQQMMAoGCCsG\n" +
                "AQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNv\n" +
                "bTBoBggrBgEFBQcBAQRcMFowLQYIKwYBBQUHMAKGIWh0dHA6Ly9wa2kuZ29vZy9n\n" +
                "c3IyL0dUU0dJQUczLmNydDApBggrBgEFBQcwAYYdaHR0cDovL29jc3AucGtpLmdv\n" +
                "b2cvR1RTR0lBRzMwHQYDVR0OBBYEFFJ56Q1CziCuxAyVY90CV7BMrgFDMAwGA1Ud\n" +
                "EwEB/wQCMAAwHwYDVR0jBBgwFoAUd8K4UJpndnaxLcKG0IOgfqZ+ukswIQYDVR0g\n" +
                "BBowGDAMBgorBgEEAdZ5AgUDMAgGBmeBDAECAjAxBgNVHR8EKjAoMCagJKAihiBo\n" +
                "dHRwOi8vY3JsLnBraS5nb29nL0dUU0dJQUczLmNybDANBgkqhkiG9w0BAQsFAAOC\n" +
                "AQEAqwctkMxmgivcpNL0VTvFi8aIdSF6M9TBqW1es7EbmzhoS/N8YCZwgX55naUd\n" +
                "riVE/SvM1S2UCw1ErF35Bp2qfIN7/e14oepcfAwQc9ryZFJGwNr6k4tTgKrJT12t\n" +
                "T8QFvy1MmX0993DZP550t7qu0xtaymrQn8356paUmkblhJLanHS4AY84cMI/WWfT\n" +
                "vv5J3Os/m3uwZGrcro3HiUIBDZNrPRm9gYtx4WhmJ4FfPtkWGtjvaJPWyKmLZZA5\n" +
                "OZfTbgOfuSfijWgbsOdu/A9cz2VufJGyqS2zPTtA0nLeBz8358sdkpAP7TC2VIP9\n" +
                "AWBQx3SbgohiAde4zLqtz/NJfQ==\n" +
                "-----END CERTIFICATE-----";
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certText.getBytes()));

        // when
        KeyStore keyStore = SecretUtil.loadK8sSecretAsKeyAndTrustStore(mountPath, "tls.key", "tls.crt", "alias", "password", "ca.crt");

        // then
        assertTrue(keyStore.getKey("alias", "password".toCharArray()) instanceof RSAPrivateCrtKey);
        assertEquals("cn=www.google.com", keyStore.getCertificateAlias(certificate));
    }

    @Test
    @DisplayName("SHOULD throw KeyStoreInitializationException WHEN certificate is not found")
    void loadK8sSecretAsKeyAndTrustStoreUnhappy() {
        // given
        String mountPath = Paths.get(this.getClass().getResource("/tls.key").getPath()).getParent().toString();

        // when - then
        assertThrows(KeyStoreInitializationException.class, () -> SecretUtil.loadK8sSecretAsKeyAndTrustStore(mountPath, "tls.key", "nope.crt", "alias", "password", "ca.crt"));
    }

}