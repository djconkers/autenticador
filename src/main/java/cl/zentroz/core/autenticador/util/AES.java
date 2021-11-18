package cl.zentroz.core.autenticador.util;

import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

public class AES
{
	private static final Logger LOGGER = Logger.getLogger(AES.class);
	private static final String CIPHER_INSTANCE = new String(new char[] {'A', 'E', 'S', '/', 'C', 'B', 'C', '/','P', 'K', 'C', 'S', '5', 'P', 'a', 'd', 'd', 'i', 'n', 'g'});

	public String desencriptar(String llaveSecreta, String textoCifrado) throws GeneralSecurityException
	{
		byte[] cipherData = Base64.getDecoder().decode(textoCifrado);
		byte[] saltData = Arrays.copyOfRange(cipherData, 8, 16);
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		final byte[][] keyAndIV = generarKeyAndIV(32, 16, 1, saltData, llaveSecreta.getBytes(StandardCharsets.UTF_8), md5);
		SecretKeySpec key = new SecretKeySpec(keyAndIV[0], "AES");
		IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);
		byte[] encrypted = Arrays.copyOfRange(cipherData, 16, cipherData.length);
		Cipher aesCBC = Cipher.getInstance(CIPHER_INSTANCE);
		aesCBC.init(Cipher.DECRYPT_MODE, key, iv);
		byte[] decryptedData = aesCBC.doFinal(encrypted);
		return new String(decryptedData);
	}

	public byte[][] generarKeyAndIV(int keyLength, int ivLength, int iterations, byte[] salt, byte[] password, MessageDigest md)
	{
		int digestLength = md.getDigestLength();
		int requiredLength = (keyLength + ivLength + digestLength - 1) / digestLength * digestLength;
		byte[] generatedData = new byte[requiredLength];
		int generatedLength = 0;
		try {
			md.reset();
			// Repita el proceso hasta que se hayan generado suficientes datos
			while (generatedLength < keyLength + ivLength) {
				// Datos de resumen (�ltimo resumen si est� disponible, datos de contrase�a, sal si est�
				// disponible)
				if (generatedLength > 0)
					md.update(generatedData, generatedLength - digestLength, digestLength);
				md.update(password);
				if (salt != null)
					md.update(salt, 0, 8);
				md.digest(generatedData, generatedLength, digestLength);
				// rondas adicionales
				for (int i = 1; i < iterations; i++) {
					md.update(generatedData, generatedLength, digestLength);
					md.digest(generatedData, generatedLength, digestLength);
				}
				generatedLength += digestLength;
			}

			// Copia la clave y el IV en conjuntos de bytes separados
			byte[][] result = new byte[2][];
			result[0] = Arrays.copyOfRange(generatedData, 0, keyLength);
			if (ivLength > 0)
				result[1] = Arrays.copyOfRange(generatedData, keyLength, keyLength + ivLength);
			return result;
		} catch (DigestException e) {
			LOGGER.error("Ha ocurrido un error al obtener KeyAndIV", e);
			return null;

		} finally {
			// Limpiar datos temporales
			Arrays.fill(generatedData, (byte) 0);
		}
	}
}