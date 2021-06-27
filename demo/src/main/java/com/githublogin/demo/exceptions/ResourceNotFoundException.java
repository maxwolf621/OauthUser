package com.githublogin.demo.exceptions;

import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.http.HttpStatus;

import lombok.Data;

@ResponseStatus(HttpStatus.NOT_FOUND)
@Data
public class ResourceNotFoundException {
    private String resourceName;
    private String fieldName;
    private Object fieldValue;
}
