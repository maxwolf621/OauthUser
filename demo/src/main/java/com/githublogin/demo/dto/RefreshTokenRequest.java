package com.githublogin.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

import io.swagger.annotations.ApiModelProperty;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenRequest {
    @NotBlank
    private String refreshToken;
    @ApiModelProperty(example = "test")
    private String username;
}
