package com.example.jose.criptografiaaes_pbe;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import java.io.IOException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class MainActivity extends AppCompatActivity {

    /*
    * Essa seção do código somente configura que algoritmo e parâmetros que
    * vamos usar. Nesse caso, usamos SHA-256 com algoritmo de hashing e AES
    * em modo CBC como algoritmo de encriptação. Vamos usar 1.000 iterações
    * da função de hashing durante o processo e terminar com uma chave de
    * 256 bits. Vamos agora especificar o algotirmo que será usado para a encriptação
    * e desencriptação real dos dados. Iremos usar AES, ainda no modo de Encadeamento de Bloco de
    * Cifra, e empregar padding PKCS#5.
    *
    * */
    private static final String PBE_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int NUM_OF_ITERATIONS = 1000;
    private static final int KEY_SIZE = 256;
    byte[] salt = "comexamplejosecriptografiaaes".getBytes();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    private void passwordPBE(String senha){
        try{
            PBEKeySpec pbeKeySpec = new PBEKeySpec(senha.toCharArray(), salt, NUM_OF_ITERATIONS, KEY_SIZE);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
            SecretKey tempKey = keyFactory.generateSecret(pbeKeySpec);
            SecretKey secretKey = new SecretKeySpec(tempKey.getEncoded(), "AES");
            Toast.makeText(this, secretKey + "", Toast.LENGTH_LONG).show();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }

    }

    public void onClickSenha(View view) {
        /*EditText editSenha = (EditText) findViewById(R.id.editSenha);
        passwordPBE(editSenha.getText().toString());*/
        fileCriptografia();
    }

    private void fileCriptografia(){
        /*
         * Aqui, configuramos o salt que será usado na computação da derivação da chave e o
         * Vetor de inicialização (IV) que será usado na encriptação e desencriptação de
         * dados.
         *
         * E preciso garantir que o IV seja, assim como salt, o mesmo todas as vezes.
         *
          * */
        byte[] salt = "comexamplejosecriptografiaaes_pbe".getBytes();
        byte[] iv = "1234567890abcdef".getBytes();

        /*
         * Aqui, simplesmente configuramos os valores que iremos encriptar e desencriptar.
          * */
        String clearTexto = "José Antônio da Silva"; // Este é o valor que será encriptado
        byte[] encryptedText;
        byte[] decryptedText;

        try{
            /*
            * Aqui, realizamos a derivação da chave, partindo da senha fornecida pelo usuário
            * até uma chave AES de 256 bits.
            * */
            PBEKeySpec pbeKeySpec = new PBEKeySpec("123".toCharArray(), salt, NUM_OF_ITERATIONS, KEY_SIZE);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
            SecretKey tempKey = keyFactory.generateSecret(pbeKeySpec);
            SecretKey secretKey = new SecretKeySpec(tempKey.getEncoded(), "AES");

            // Então, defina o valor da Initialization Vector(IV)
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            /*
            * Este é o centro de nosso exemplo. Usamos a chave derivada e o IV, com nossa especificação
            * de que parâmetros de encriptação queremos usar, para formar um objeto Cipher.
            *
            * */
            Cipher encCipher = Cipher.getInstance(CIPHER_ALGORITHM);
            encCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            Cipher decCipher = Cipher.getInstance(CIPHER_ALGORITHM);
            decCipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            /*
            * Uma Vez que tenhamos os objetos Cipher, podemos realizar as operações de encriptação e desencriptação.
            * Primeiro, vamos encriptar.
            * Enviamos a String que queremos encriptar (convertido em um array de bytes) para o método doFinal()
            * do objeto Cipher encriptador. A operação de encriptação é realizada e os bytes encriptados resultantes
            * são retornados para nós.
            * */
            encryptedText = encCipher.doFinal(clearTexto.getBytes());

            /*
            * Podemos também desencriptar dados usando a mesma abordagem.
            * */
            decryptedText = decCipher.doFinal(encryptedText);
            String sameAsClearText = new String(decryptedText);

            String textCript = new String(encryptedText);
            Toast.makeText(this, textCript, Toast.LENGTH_LONG).show();

            Toast.makeText(this, sameAsClearText, Toast.LENGTH_LONG).show();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException | BadPaddingException | InvalidKeyException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }


    private void connectSSL(String url) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, KeyManagementException {
        /*
        * Esse código lê recursos bruto que é, na verdade, o keystore BKS e o usa como objeto classe KeyStore.
        * */
        KeyStore selfsignedKeys = KeyStore.getInstance("BKS");
        selfsignedKeys.load(this.getResources().openRawResource(R.raw.selfsignedcert1), "To35@nny85".toCharArray());

        /*
         * Isso cria um TrustManagerFactory que produzirá objetos TrustManager que usam os
         * algoritmos SSL/TLS padrão (é isso que faz o método getDefaultAlgorithm()) e utilizará
         * nosso keystore personalizado, que é configurado na chamada init() que envia esse keystore, para
         * decidir em que certificados de servidor confiar.
         *
          * */
        TrustManagerFactory trustMrg = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustMrg.init(selfsignedKeys);

        /*
         * A chamada para o init() utiliza três parâmetros:
         *  1 - as fontes das chaves usadas do lado do cliente, as fontes de confiança e as fontes de aleatoriedade
         *      como não estamos realizando SSL/TLS onde o servidor autentica o cliente, mas somente onde o cliente autoriza
         *      o autoriza o servidor, utiliza null.
         *  2 - O segundo parâmetro é onde fornecemos a lista TrustManager gerada pelo TrustManagerFactory.
         *  3 - Os números aleatorios necessários para SSL/TLS são gerados. Aqui estamos usando uma instancia SecureRandom.
          * */
        SSLContext selfsignedSSLContext = SSLContext.getInstance("TLS");
        selfsignedSSLContext.init(null, trustMrg.getTrustManagers(), new SecureRandom());

        /*
        * O método estático setDefaultSSLSocketFactory() da classe HttpsURLConnection é chamado. Esse método
        * muda o SSLSocketFactory usado para criar novas conexões SSL/TSL
        * */
        HttpsURLConnection.setDefaultSSLSocketFactory(selfsignedSSLContext.getSocketFactory());

        /* Conexão feita exclusivamente para o servidor assinado */
        URL serveURL = new URL(url);
        HttpsURLConnection serveConn = (HttpsURLConnection) serveURL.openConnection();
    }
}
