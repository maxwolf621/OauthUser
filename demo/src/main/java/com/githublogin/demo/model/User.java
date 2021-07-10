package com.githublogin.demo.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import static javax.persistence.GenerationType.IDENTITY;
import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonIgnore;

import io.swagger.annotations.ApiModel;

import java.time.Instant;

// Annotation : 
//  '---> https://springbootdev.com/2018/03/13/spring-data-jpa-auditing-with-createdby-createddate-lastmodifiedby-and-lastmodifieddate/

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "user", uniqueConstraints = {
    @UniqueConstraint(columnNames = "mail")
})
@ApiModel( value = "User Model", description = "To store the user information") 
public class User {
    @Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "user_id", unique = true, nullable =false)
    private long userId ;
    
    @NotBlank(message="UserName required")
    @Column(name = "user_name")
    private String username ;
    
    //@NotBlank(message = "Password required")
    @JsonIgnore
    @Column(name = "password")
    private String password;
    
    @Email
    @Column(name = "mail")
    private String mail;

    @Column(name = "created_date")
    private Instant createdDate;
    
    @Column(name = "legit")
    private boolean legit ;

    @Column(name = "auth_provider")
    private AuthProviderType authProvider;
}

