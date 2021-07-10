package com.githublogin.demo.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    @ApiModelProperty(example = "test")
    private String username;
    @ApiModelProperty(example = "1234")
    private String password;
    @ApiModelProperty(example = "123456@gmail.com")
    private String mail   ;
}
