package com.githublogin.demo.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

import io.swagger.annotations.ApiModelProperty;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RefreshTokenResponse {
    @ApiModelProperty(value = "JWT")
    private String  Token;
    @ApiModelProperty(value = "Not JWT")
    private String  refreshToken;
    private Instant expiresAt;
    private String  username;
}