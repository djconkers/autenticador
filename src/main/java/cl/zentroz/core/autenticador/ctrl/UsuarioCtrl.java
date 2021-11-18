package cl.zentroz.core.autenticador.ctrl;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import cl.zentroz.biblioteca.ctrl.ControladorListar;
import cl.zentroz.biblioteca.ctrl.ControladorObtener;
import cl.zentroz.biblioteca.dto.MensajeError;
import cl.zentroz.biblioteca.util.Constantes;
import cl.zentroz.core.autenticador.dto.Usuario;
import cl.zentroz.core.autenticador.srv.UsuarioServicio;
import cl.zentroz.core.autenticador.util.JwtUtil;
@RestController
@RequestMapping("/usuario")
public class UsuarioCtrl implements ControladorListar<Usuario>,ControladorObtener<Usuario>
{
	private static final Logger LOGGER = Logger.getLogger(UsuarioCtrl.class);
	
	
	@Autowired
	private UsuarioServicio srv;
	
	
	@Autowired
	private JwtUtil tokenProvider;
	
	@PutMapping(value = "/recuperarPassword")
	public ResponseEntity<Object> recuperarPassword(
			@RequestHeader(required = false, name = Constantes.AUTORIZACION_HEADER) String token,
			@RequestBody Usuario entidad)
	{
		
		try 
		{
			if(srv.recuperarPassword(entidad))
			{
				HashMap<String,Object> retorno = new HashMap<>();
				retorno.put("estado", true);
				return new ResponseEntity<>(retorno,HttpStatus.OK);
			}
			else 
			{
				MensajeError msj = new MensajeError("E-CTRL-RECUPERAR-PASSWORD-001", this.obtieneClaseEntidad().getSimpleName() + " Error al recuperar password", true);
				return new ResponseEntity<>(msj, HttpStatus.BAD_REQUEST);
			}
		} catch (NoSuchAlgorithmException | MessagingException e) 
		{
			LOGGER.error("E-CTRL-RECUPERAR-PASSWORD-000", e);
			MensajeError msj = new MensajeError("E-CTRL-RECUPERAR-PASSWORD-000", this.obtieneClaseEntidad().getSimpleName() + " Error al recuperar password", true);
			return new ResponseEntity<>(msj, HttpStatus.BAD_REQUEST);
		}

		
		
	}
	
	@PutMapping(value = "/actualizarPassword")
	public ResponseEntity<Object> actualizarPassword(@RequestBody Usuario entidad)
	{
		try 
		{
			if(srv.actualizarPassword(entidad))
			{
				HashMap<String,Object> retorno = new HashMap<>();
				retorno.put("estado", true);
				return new ResponseEntity<>(retorno,HttpStatus.OK);
			}
			else 
			{
				MensajeError msj = new MensajeError("E-CTRL-ACTUALIZAR-PASSWORD-001", this.obtieneClaseEntidad().getSimpleName() + " Error al actualizar password", true);
				return new ResponseEntity<>(msj, HttpStatus.BAD_REQUEST);
			}
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("E-CTRL-ACTUALIZAR-PASSWORD-000", e);
			MensajeError msj = new MensajeError("E-CTRL-ACTUALIZAR-PASSWORD-000", this.obtieneClaseEntidad().getSimpleName() + " Error al actualizar password", true);
			return new ResponseEntity<>(msj, HttpStatus.BAD_REQUEST);
		}
		
		
	}
	
	@GetMapping(value = "/refrescarToken")
	public ResponseEntity<Object> refrescarToken(@RequestHeader(Constantes.AUTORIZACION_HEADER) String token, HttpServletRequest request)
	{
		if(token!=null)
			token=token.replace(Constantes.BEARER, "");
		else 
		{
			MensajeError msj = new MensajeError("E-CTRL-REFRESCAR-TOKEN-000", this.obtieneClaseEntidad().getSimpleName() + " No existe token", true);
			return new ResponseEntity<>(msj,HttpStatus.UNAUTHORIZED);
		}
		if(!tokenProvider.validarToken(token))
		{
			MensajeError msj = new MensajeError("E-CTRL-REFRESCAR-TOKEN-000", this.obtieneClaseEntidad().getSimpleName() + " Token invalido", true);
			return new ResponseEntity<>(msj,HttpStatus.UNAUTHORIZED);
		}
		HashMap<String,Object> retorno = new HashMap<>();
		Usuario u = tokenProvider.getUserFromJWT(token);
		retorno.put("estado", false);
		String newToken = tokenProvider.makeToken(request, u);
		newToken = Constantes.BEARER+newToken;
		retorno.put("token", newToken);
		return new ResponseEntity<>(retorno,HttpStatus.OK);
		
	}
	
	@Override
	public UsuarioServicio getServicio() {
		// TODO Auto-generated method stub
		return srv;
	}
}
