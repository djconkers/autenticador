package cl.zentroz.core.autenticador.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.xml.bind.DatatypeConverter;

import cl.zentroz.biblioteca.excepciones.ExcepcionBase;


public class SeguridadUtil 
{
	private SeguridadUtil() 
	{
		
	}
	
	public static String getEncodedPassword(String plainText)
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
	        byte[] digest = md.digest(plainText.getBytes(StandardCharsets.UTF_8));
	        return DatatypeConverter.printHexBinary(digest).toLowerCase();
		} catch (Exception e) {
			throw new ExcepcionBase("Error al cifrar contraseña", e);
		}
	}
}
