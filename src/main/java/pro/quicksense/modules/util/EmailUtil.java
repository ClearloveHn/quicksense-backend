package pro.quicksense.modules.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import pro.quicksense.modules.common.CommonConstant;

import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class EmailUtil {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private CodeUtil codeUtil;

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Value("${spring.mail.username}")
    private String from;

    @Value("${app.email.expiration-minutes:3}")
    private int expirationTimeInMinutes;

    @Value("${app.email.subject:QuickSense Registration}")
    private String emailSubject;


    public void sendSimpleMail(String toEmail) {
        if (isInvalidEmail(toEmail)) {
            log.error("Invalid email address: {}", toEmail);
            throw new IllegalArgumentException("Invalid email address");
        }

        String verificationCode = codeUtil.generateVerificationCode();
        String key = CommonConstant.KEY_PREFIX + toEmail;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(toEmail);
        message.setSubject(emailSubject);
        message.setText(String.format(
                "Welcome to QuickSense!\n\n" +
                        "Your verification code is: %s\n\n" +
                        "Please keep it safe.\n\n" +
                        "This code will expire in %d minutes.\n\n" +
                        "If you didn't request this code, please ignore this email.",
                verificationCode, expirationTimeInMinutes
        ));

        try {
            mailSender.send(message);
            redisTemplate.opsForValue().set(key, verificationCode, expirationTimeInMinutes, TimeUnit.MINUTES);
            log.info("Verification code sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send email to: {}", toEmail, e);
            throw new RuntimeException("Failed to send email", e);
        }
    }

    public boolean isInvalidEmail(String email) {
        String emailPattern = "^[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)+$";
        return !email.matches(emailPattern);
    }
}