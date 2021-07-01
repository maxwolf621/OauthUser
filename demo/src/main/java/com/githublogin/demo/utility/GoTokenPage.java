package com.githublogin.demo.utility;

import lombok.experimental.UtilityClass;

@UtilityClass
public class GoTokenPage {
    private static final String TOKENPAGE = "http://localhost:8080/api/auth/accountVerification/";
    public String url(){
        return TOKENPAGE;
    }
}
