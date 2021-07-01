package com.githublogin.demo.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Async;

import javax.mail.internet.MimeMessage;
import org.springframework.stereotype.Service;

import com.githublogin.demo.model.NotificationMail;


@Service
@AllArgsConstructor
@Slf4j
public class SendMailService {

   @Value("${tokeurl.sendby}")
   private final String Email;
   private final JavaMailSender toSend;
   private final MailBodyBuilder mailbodybuilder;

   @Async
   public void SendTokenMail(NotificationMail userMail){
      // via MimeMessageHelper to set up mail
      MimeMessagePreparator preparator = new MimeMessagePreparator() {
         @Override
         public void prepare(MimeMessage mimeMessage) throws Exception {
            MimeMessageHelper message = new MimeMessageHelper(mimeMessage);
            message.setFrom(Email);
            message.setTo(userMail.getRecipient());
            message.setSubject(userMail.getSubject());
            message.setText(mailbodybuilder.BuilderHTMLContent(userMail.getBody()));
         }
      };
      try {
      // send the mail via MimeMessagePreparator
         toSend.send(preparator);
         log.info("Sent The Mail Successfully");
      }
      catch(MailException e){
         
         log.warn("Fial to Send The Mail to" + userMail.getRecipient());
         throw new RuntimeException("Fial to send mail to " + userMail.getRecipient());
      }
   }
}
