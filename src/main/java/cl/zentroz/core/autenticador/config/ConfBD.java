package cl.zentroz.core.autenticador.config;

import org.springframework.context.annotation.Configuration;

import cl.zentroz.biblioteca.ConfiguracionBD;

@Configuration
public class ConfBD extends ConfiguracionBD
{
	public ConfBD() {
		super("java:/autenticador");
	}
}
