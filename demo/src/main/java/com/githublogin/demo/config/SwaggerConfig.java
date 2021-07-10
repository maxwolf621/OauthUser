package com.githublogin.demo.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

//import io.swagger.models.Tag;
import springfox.documentation.service.Contact;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
//import springfox.documentation.swagger2.annotations.EnableSwagger2;
import springfox.documentation.service.ApiInfo;


/**
 * The Swagger version : swaggerfox 3.0.0
 */
//@EnableSwagger2 /** use only version below swaggerfox 3.0.0 */
@Configuration
public class SwaggerConfig implements WebMvcConfigurer {
    @Value("${swaggerInfo.name}")
    private String name;
    @Value("${swaggerInfo.mail")
    private String mail;
    @Value("${swaggerInfo.url")
    private String url;

    // For mapping swagger-ui html
    // https://stackoverflow.com/questions/43545540/swagger-ui-no-mapping-found-for-http-request
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {

        registry.addResourceHandler("swagger-ui.html")
                .addResourceLocations("classpath:/META-INF/resources/");

        registry.addResourceHandler("/webjars/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/");
    }

    /** 
     * Swagger 2.x.x version 
     *          
                 
    @Bean   
    public Docket apiDocket(){
        return new Docket(DocumentationType.SWAGGER_2).apiInfo((ApiInfo) getApiInfo()).select()
                 // NDICATE swagger only funtions api's url in this Control 
                 // .apis(RequestHandlerSelector.basePackge("com.demo.scanOlnyThis_Controller"))
                .apis(RequestHandlerSelectors.any()) // file(java packages) filter : any
                .paths(PathSelectors.any()) // API's url path filter: any
                .build();

            

    }
    */
    @Bean
    public Docket apiDocket(){
        return new Docket(DocumentationType.OAS_30).apiInfo((ApiInfo) getApiInfo()).select()
                    .apis(RequestHandlerSelectors.any()) // file(java packages) filter : any
                    .paths(PathSelectors.any()) // API's url path filter: any
                    .build();
    }

    private Object getApiInfo() {
        return new ApiInfoBuilder()
                .title("Swagger API Info")
                .version("1.0")
                .description("Spring Boot Project")
                .contact(new Contact(name,url,mail)) //.license("Apache License Version 2.0")
                .build();
    }
}
