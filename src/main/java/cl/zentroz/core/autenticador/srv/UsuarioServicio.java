package cl.zentroz.core.autenticador.srv;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import cl.zentroz.biblioteca.srv.Servicio;
import cl.zentroz.core.autenticador.dao.UsuarioDao;
import cl.zentroz.core.autenticador.dto.Usuario;
@Service
public class UsuarioServicio extends Servicio<UsuarioDao, Usuario>
{
	@Autowired
    private JavaMailSender mailSender;
	
	private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$.-_*abcdefghijklmnopqrstuvwxyz";
	public boolean recuperarPassword(Usuario entidad) throws NoSuchAlgorithmException, MessagingException
	{
		boolean retorno = false;
		Usuario u = dao.obtener(entidad);
		String newPass = randomAlphaNumeric(10);
		String hashPass = encriptarPassword(newPass);
		u.setPassword(hashPass);
		int i = dao.updateUsuarioPass(u);
		if(i>-1)
			enviarHTMLMail(u,newPass);
		return retorno;
	}
	
	public boolean actualizarPassword(Usuario entidad) throws NoSuchAlgorithmException 
	{
		String hashPass = encriptarPassword(entidad.getPassword());
		Usuario u = dao.obtener(entidad);
		u.setPassword(hashPass);
		int i = dao.updateUsuarioPass(u);
		return (i>-1);
	}
	
	
	private String encriptarPassword(String pass) throws NoSuchAlgorithmException 
	{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(pass.getBytes(StandardCharsets.UTF_8));
		String password = DatatypeConverter.printHexBinary(digest).toLowerCase();
		return password;
	}
	
	private String randomAlphaNumeric(int count)
	{
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = new Random().nextInt(ALPHA_NUMERIC_STRING.length());
			builder.append(ALPHA_NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}
	
	private void enviarHTMLMail(Usuario u,String pass) throws MessagingException 
    {
		String contenido = "<html>";
		contenido+="<body>";
		contenido+="<p><b>Su contraseña es:<b></p>";
		contenido+="<p>"+pass+"</p>";
		contenido+="</body>";
		contenido+="</html>";

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, false, "utf-8");
        helper.setTo(u.getCorreo());
        message.setFrom("no-reply@michisaurios.ddns.net");
        helper.setSubject("Recuperacion de contraseña");   
        message.setContent(contenido, "text/html");
        mailSender.send(message);
    }
	
}
