package com.githublogin.demo;

import com.githublogin.demo.config.OAuth2Properties;
// import com.githublogin.demo.config.SwaggerConfig; /** Using EnableOpenApi instread */

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
// import org.springframework.context.annotation.Import; /**@Import */
import org.springframework.scheduling.annotation.EnableAsync;

import springfox.documentation.oas.annotations.EnableOpenApi;

@SpringBootApplication
@EnableAsync
@EnableConfigurationProperties(OAuth2Properties.class)
@EnableOpenApi
//@Import(SwaggerConfig.class) /** swagger 2.x version */
public class DemoApplication {
	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

}
