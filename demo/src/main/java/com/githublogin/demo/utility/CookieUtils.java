package com.githublogin.demo.utility;

import org.springframework.util.SerializationUtils;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;
import java.util.Optional;

@Slf4j
@UtilityClass
public class CookieUtils {

    // get the cookie from request payload sent by user agent(application/clinet/browser)
    public static Optional<Cookie> getCookie(HttpServletRequest request, String cookieName) {
        log.info(" '----> CookieUtils getCookie");
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(cookieName)) {
                    log.info("  '___getCookie: " + cookieName);
                    return Optional.of(cookie);
                }
            }
        }
        // return null if there is no cookies in request payload 
        log.info(" '___There are no cookies in this http servlet Request");
        return Optional.empty();
    }

    //set up a cookie and add it in the response payload
    public static void addCookie(HttpServletResponse response, String cookieName, String cookieValue, int maxAge) {
        log.info(" '-----> CookieUtils addCookie");
        log.info("  '_______Cookie Value: " + cookieValue);
        log.info("  '_______Cookie Name: " + cookieName);
        Cookie cookie = new Cookie(cookieName, cookieValue);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    // request payload included cookies and sent to httpservlet
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String cookieName) {
        log.info(" '-----> CookieUtils deleteCookie");
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie: cookies) {
                /**
                 - responsepayload will send back to client 
                 - cookie.setMaxAge(0)
                       '-----> Once client receives the response. 
                               It deletes the cookie stored in client.
                */
                if (cookie.getName().equals(cookieName)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }
    }

    // Seralize the data
    public static String serialize(Object object) {
        log.info("  '----> serialize data");
        return Base64.getUrlEncoder()
                .encodeToString(SerializationUtils.serialize(object));
    }

    // deserialize the data
    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        log.info("  '----> deserialize data");
        return cls.cast(SerializationUtils.deserialize(
                        Base64.getUrlDecoder().decode(cookie.getValue())));
    }
}