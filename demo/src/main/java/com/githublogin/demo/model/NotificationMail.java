package com.githublogin.demo.model;

import lombok.Data;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class NotificationMail {
    private String subject;
    private String recipient;
    private String body;
}

