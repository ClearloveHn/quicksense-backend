package pro.quicksense.modules.service;

import com.baomidou.mybatisplus.extension.service.IService;
import org.springframework.http.ResponseEntity;
import pro.quicksense.modules.entity.EmailLoginRequest;
import pro.quicksense.modules.entity.LoginRequest;
import pro.quicksense.modules.entity.User;


public interface UserService extends IService<User> {
    ResponseEntity<?> registerUser(User user);

    ResponseEntity<?> login(LoginRequest loginRequest);

    ResponseEntity<?> loginByEmail(EmailLoginRequest request);

    ResponseEntity<?> editUser(User user);

    ResponseEntity<?> getUserInfo(String userId);

    ResponseEntity<?> sendEmail(String email);
}