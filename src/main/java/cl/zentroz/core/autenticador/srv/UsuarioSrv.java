package cl.zentroz.core.autenticador.srv;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import cl.zentroz.core.autenticador.dao.UsuarioDao;
import cl.zentroz.core.autenticador.dto.Usuario;

@Service
public class UsuarioSrv implements UserDetailsService
{
	private static final Logger LOGGER = Logger.getLogger(UsuarioSrv.class);
	@Autowired
	private UsuarioDao usuarioDao;
	private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException 
	{
		Usuario entidad = new Usuario();
		entidad.setUsuario(username);
		entidad = usuarioDao.obtener(entidad);
		entidad.setPassword(encoder.encode(entidad.getPassword()));
		if(LOGGER.isDebugEnabled())
			LOGGER.debug("Usuario ["+entidad+"]");
		List<GrantedAuthority> roles = new ArrayList<GrantedAuthority>();
		roles.add(new SimpleGrantedAuthority("NONE"));
		return new User(entidad.getUsuario(),entidad.getPassword(),true,true,true,true,roles);
	}
	
	public int bloqueaUsuario(Usuario entidad) 
	{
		return usuarioDao.modificar(entidad);
	}
	
}
