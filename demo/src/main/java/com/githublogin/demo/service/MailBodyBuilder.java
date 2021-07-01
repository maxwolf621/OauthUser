package com.githublogin.demo.service;

import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor // for TemplateEngine
public class MailBodyBuilder {
    private final TemplateEngine templateEngine;
    public String BuilderHTMLContent(String content){
            Context context = new Context();
            context.setVariable("content", content);
            return templateEngine.process("mailTemplate", context);
    }
}
