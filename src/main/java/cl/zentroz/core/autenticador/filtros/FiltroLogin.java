package cl.zentroz.core.autenticador.filtros;

import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import cl.zentroz.biblioteca.util.Constantes;
import cl.zentroz.core.autenticador.dto.Usuario;
import cl.zentroz.core.autenticador.srv.UsuarioSrv;
import cl.zentroz.core.autenticador.util.AES;
import cl.zentroz.core.autenticador.util.JwtUtil;
import cl.zentroz.core.autenticador.util.SeguridadUtil;

public class FiltroLogin extends AbstractAuthenticationProcessingFilter {
	protected static final Logger LOGGER = Logger.getLogger(FiltroLogin.class);

	protected Usuario user = new Usuario();
	protected int intentos = 0;
	protected int intentosConf=100;
	@Autowired
	protected JwtUtil tokenProvider;
	@Autowired
	protected UsuarioSrv usuarioService;


	public FiltroLogin(String url, AuthenticationManager authManager) {
		super(new AntPathRequestMatcher(url));
		setAuthenticationManager(authManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {
		try 
		{
			// Obtengo el contenido de la peticion enviada al Login
			InputStream body = request.getInputStream();
			// Mappeo el JSON enviado a mi clase Usuario
			this.user = new ObjectMapper().readValue(body, Usuario.class);
			// Seteo la contraseña en MD5 para su comparacion con spring security
			try 
			{
				AES aes = new AES();
				String keyAES = new String(Base64.getDecoder().decode(Constantes.SECRET_KEY_AES.getBytes()));
				user.setPassword(aes.desencriptar(keyAES, user.getPassword()));
			} catch (Exception e) {
				LOGGER.error("Ha Ocurrido un error al decifrar contraseña", e);
			}
			user.setPassword(SeguridadUtil.getEncodedPassword(user.getPassword()));
			if(LOGGER.isDebugEnabled())
				LOGGER.debug("Usuario ["+user+"]");
		} catch (Exception e) {
			LOGGER.error("E-FILTER-LOGIN, ocurrio un error en login", e);
		}
		// Realizo la Autentificacion con el autenticador de Spring enviandole el
		// usuario y contraseña
		UsernamePasswordAuthenticationToken upat = new UsernamePasswordAuthenticationToken(
				user.getUsuario(),
				user.getPassword(),
				Collections.emptyList());
		return getAuthenticationManager().authenticate(upat);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication auth) throws IOException, ServletException {
		intentos = 0;
		// Si la autenticacion es correcta, genero en token con JWT
		response.addHeader("access-control-expose-headers", "Authorization");
		tokenProvider.generateToken(response, request, this.user);
		// Generamos la respuesta Json para el body
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("ultimo_login", "");
		response.setContentType("application/json");
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(HttpServletResponse.SC_OK);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		intentos++;
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("mensaje", "Error de autenticación: usuario o password incorrecto!");
		body.put("error", failed.getMessage());
		LOGGER.error("unsuccessfulAuthentication",failed);
		if (intentos >= intentosConf) {// Cuenta bloqueada por cantidad de intentos
			if (intentos == intentosConf) {// If para que solo haga 1 update a la bd
				usuarioService.bloqueaUsuario(user);
			}
			body.put("mensaje", "Error de autenticación: usuario o password incorrecto!");
		}
		response.setContentType("application/json");
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(401);
	}
}