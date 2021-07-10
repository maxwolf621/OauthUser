package com.githublogin.demo.dto;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// the client loging request to authenticationservice

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {
    @ApiModelProperty(example = "test")
    private String username;
    @ApiModelProperty(example = "1234")
    private String password;   
}
