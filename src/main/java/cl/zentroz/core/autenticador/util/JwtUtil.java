package cl.zentroz.core.autenticador.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Component;

import cl.zentroz.biblioteca.util.Constantes;
import cl.zentroz.core.autenticador.dto.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.text.SimpleDateFormat;
import java.util.Date;

@Component("JwtUtil")
public class JwtUtil 
{
	private static final Logger log = Logger.getLogger(JwtUtil.class);

	public void generateToken(HttpServletResponse response, HttpServletRequest request, Usuario user) {
		String token = makeToken(request, user);
		addTokenHeader(response, token);
	}

	public String makeToken(HttpServletRequest request, Usuario user) {
		// Otengo la fecha actual en mili segundo
		long tiempo = System.currentTimeMillis();
		// Genero el token con el builder de la libreria JWT
		byte[] keyBytes = Decoders.BASE64.decode(Constantes.SUPER_SECRET_KEY);
		Key key = Keys.hmacShaKeyFor(keyBytes);
		SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd HH:mm:ss");
		String token = Jwts.builder()
			//Selecciono el tipo de encriptacion y la clave para encriptarlo
			.signWith(key)
			//Se agrega al token el nombre del usuario
			.setSubject(user.getUsuario())
			//Se agrega al token la fecha de creacion
			.setIssuedAt(new Date(tiempo))
			//Se agrega al token la fecha de expiracion (fecha de creacion + tiempo de exp en mili segundos)
			.setExpiration(new Date(tiempo+Constantes.TOKEN_EXPIRATION_TIME))
			//Con el metodo claim se agregan datos extras al token como la IP, URL, etc.
			.claim("idUsuario",user.getIdIncremental())
			.claim("correo",user.getCorreo())
			.claim("fechaCreacionToken",sdf.format(new Date(tiempo)))
			.claim("fechaExpiracionToken",sdf.format(new Date(tiempo+Constantes.TOKEN_EXPIRATION_TIME)))
			.claim("usuario",user.getUsuario())
			.claim("IP", request.getRemoteAddr())
			.claim("URI", request.getRequestURI())
			.claim("URL", request.getRequestURL().toString())
			//Compacto el token
			.compact();

		// Obtengo el token del header
		// Si existe, le remplazo el Prefijo beared
		if (token != null) {
			token = token.replace(Constantes.BEARER, "");
		}
		return token;
	}

	public void addTokenHeader(HttpServletResponse response, String token) {
		response.addHeader(Constantes.HEADER_AUTORIZACION, Constantes.BEARER + token);
	}

	@SuppressWarnings("deprecation")
	public Usuario getUserFromJWT(String token) {
		Usuario user = new Usuario();
		// Parseo el token
		Claims claims = Jwts.parser()
				// desencripto el token con la clave
				.setSigningKey(Constantes.SUPER_SECRET_KEY)
				// parseo los claims que posee el token (nombre de usuario, fecha de creacion,
				// expiracion, etc)
				.parseClaimsJws(token)
				// Obtengo todos los claims del cuerpo
				.getBody();
		// retorno solo el claim de usuario
		user.setUsuario(claims.getSubject());
		return user;
	}

	@SuppressWarnings("deprecation")
	public boolean validarToken(String authToken) {
		try {
			// Parseo el token
			Jwts.parser()
					// desencripto el token con la clave
					.setSigningKey(Constantes.SUPER_SECRET_KEY)
					// parseo los claims que posee el token
					.parseClaimsJws(authToken);
			return true;
		} catch (MalformedJwtException ex) {
			log.error("Invalid JWT token: " + authToken);
		} catch (ExpiredJwtException ex) {
			log.error("Expired JWT token: " + authToken);
		} catch (UnsupportedJwtException ex) {
			log.error("Unsupported JWT token: " + authToken);
		} catch (IllegalArgumentException ex) {
			log.error("JWT claims string is empty: " + authToken);
		}
		return false;
	}
}