package cl.zentroz.core.autenticador.config;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import cl.zentroz.core.autenticador.filtros.FiltroJwt;
import cl.zentroz.core.autenticador.filtros.FiltroLogin;
import cl.zentroz.core.autenticador.srv.UsuarioSrv;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
public class ConfiguracionSeguridad extends WebSecurityConfigurerAdapter 
{

	private static final String URL_LOGIN="/login";
	private static final String URL_REGISTRAR="/usuario/agregar";
	private static final String URL_RECUPERAR_CLAVE="/usuario/recuperarPassword";
	
	@Autowired
	private UsuarioSrv userDetailsService;
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		// Encryptador para las contraseñas
		return new BCryptPasswordEncoder();
	}

	/**
	 *
	 * Se Transformaron ambos Filtros en Bean para que Spring instanciara
	 * automaticamente todas las clases que usan estos filtros con la anotacion
	 * Autowired
	 *
	 */
	@Bean
	public FiltroLogin loginFilter() throws Exception {
		// Filtro para realizar el login
		return new FiltroLogin(URL_LOGIN, authenticationManager());
	}

	@Bean
	public FiltroJwt jwtFilter() {
		// Filtros para el resto de peticiones
		return new FiltroJwt();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// Se define la clase que recupera los usuarios y el algoritmo para procesar las
		// passwords
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
			//Se Desabitila el CORS y CSRF
			.cors()
			.and()
			.csrf()
			.disable()
			//Se inicia el manejador de sesiones
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
			//se inicia el autorizador de peticiones
			.authorizeRequests()
			//Se Permite el acceso a la URL del login
			.antMatchers(URL_LOGIN).permitAll()
			.antMatchers(URL_REGISTRAR).permitAll()
			.antMatchers(URL_RECUPERAR_CLAVE).permitAll()
			//El resto de las peticiones necesita autenticacion
			.anyRequest().authenticated()
			//y se agregan filtros
			.and()
			//Filtro para el Login
			.addFilterBefore(loginFilter(),UsernamePasswordAuthenticationFilter.class)
			//Filtro Para el resto de peticiones
			.addFilterBefore(jwtFilter(),UsernamePasswordAuthenticationFilter.class)
			.headers().contentTypeOptions().disable().frameOptions().disable().xssProtection().disable()
			;
	}

}
