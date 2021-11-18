package cl.zentroz.core.autenticador;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.PropertySource;

@SpringBootApplication
@PropertySource({"classpath:application.properties"})
public class ApiAutenticadorApplication extends SpringBootServletInitializer
{
	public static void main(String[] args) 
	{
		SpringApplication.run(ApiAutenticadorApplication.class, args);
	}

	@Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) 
	{
        return application.sources(ApiAutenticadorApplication.class);
    }
}