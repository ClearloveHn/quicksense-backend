package pro.quicksense.modules.service.impl;


import cn.hutool.core.util.ObjectUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import pro.quicksense.modules.common.CommonConstant;
import pro.quicksense.modules.entity.EmailLoginRequest;
import pro.quicksense.modules.entity.LoginRequest;
import pro.quicksense.modules.entity.User;
import pro.quicksense.modules.mapper.UserMapper;
import pro.quicksense.modules.service.UserService;
import pro.quicksense.modules.util.CodeUtil;
import pro.quicksense.modules.util.EmailUtil;
import org.springframework.http.ResponseEntity;
import pro.quicksense.modules.util.JwtInterceptor;



import java.util.ArrayList;
import java.util.Date;
import java.util.List;


@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

    private final EmailUtil emailUtil;
    private final CodeUtil codeUtil;
    private final JwtInterceptor jwtInterceptor;

    public ResponseEntity<?> registerUser(User user) {
        // Perform all validations
        ResponseEntity<?> validationResult = validateUser(user);
        if (validationResult != null) {
            return validationResult;
        }

        try {
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user.setCreateTime(new Date());
            user.setStatus(CommonConstant.USER_STATUS_NORMAL);
            this.save(user);
        } catch (DataIntegrityViolationException e) {
            log.error("Username or email already exists", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Username or email already exists");
        } catch (Exception e) {
            log.error("Error during user registration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred during registration");
        }

        return ResponseEntity.ok("User registration successful");
    }

    public ResponseEntity<?> login(LoginRequest loginRequest) {
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUsername, loginRequest.getUsername());
        User user = this.getOne(queryWrapper);

        // Check if the user exists and is effective
        ResponseEntity<?> checkResult = checkUserIsEffective(user);
        if (checkResult != null) {
            return checkResult;
        }

        // Check if the username or password is correct
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        boolean matches = passwordEncoder.matches(loginRequest.getPassword(), user.getPassword());
        if (!matches) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Incorrect username or password");
        }

        // Login successful, generate token and return
        String token = jwtInterceptor.generateToken(user);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    public ResponseEntity<?> loginByEmail(EmailLoginRequest request) {

        // verify code check
        if (!codeUtil.verifyCode(request.getEmail(), request.getVerifyCode(), CommonConstant.KEY_PREFIX)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Verification code error");
        }

        // Check if the user exists
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getEmail, request.getEmail());
        User user = this.getOne(queryWrapper);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User not found");
        }

        // Login successful, generate token and return
        String token = jwtInterceptor.generateToken(user);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    public ResponseEntity<?> editUser(User user) {
        try {
            user.setUpdateTime(new Date());
            this.updateById(user);
        } catch (Exception e) {
            log.error("Error during user edit", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred during user edit");
        }
        return ResponseEntity.ok("User edit successful");
    }

    public ResponseEntity<?> getUserInfo(String userId) {
        List<User> userList = new ArrayList<>();
        if (StringUtils.isNotBlank(userId)) {
            User user = this.getById(userId);
            userList.add(user);
        } else {
            userList = this.list();
        }
        return ResponseEntity.ok(userList);
    }


    public ResponseEntity<?> sendEmail(String email) {

        try {
            emailUtil.sendSimpleMail(email);
        } catch (Exception e) {
            log.error("Error during email sending", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred during email sending");
        }

        return ResponseEntity.ok("Email sent successfully");
    }

    private ResponseEntity<?> checkUserIsEffective(User user) {

        // The user does not exist
        if (ObjectUtil.isEmpty(user)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("The user does not exist. Please sign up.");
        }

        // The user account is frozen.
        if (CommonConstant.USER_STATUS_FROZEN.equals(user.getStatus())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("The user account is frozen.");
        }

        return null; // The user is valid
    }

    private ResponseEntity<?> validateUser(User user) {

        if (StringUtils.isBlank(user.getUsername())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username cannot be empty");
        }

        if (StringUtils.isBlank(user.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email cannot be empty");
        }

        if (StringUtils.isBlank(user.getPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Password cannot be empty");
        }

        if (StringUtils.isBlank(user.getConfirmPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Confirm password cannot be empty");
        }

        if (StringUtils.isBlank(user.getRealname())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Real name cannot be empty");
        }

        if (StringUtils.isBlank(user.getVerifyCode())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("verifyCode cannot be empty");
        }

        // Validate email address format
        if (emailUtil.isInvalidEmail(user.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid email format");
        }

        // Validate password format
        if (!isValidPassword(user.getPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Password must contain letters, numbers, and special characters, and be 8-20 characters long");
        }

        // Check if password and confirm password are equal
        if (!user.getPassword().equals(user.getConfirmPassword())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Password and confirm password do not match");
        }

        // Email verification
        if (!codeUtil.verifyCode(user.getEmail(), user.getVerifyCode(), CommonConstant.KEY_PREFIX)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Verification code error");
        }

        return null; // Validation passed
    }

    private boolean isValidPassword(String password) {
        String passwordPattern = "^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,20}$";
        return password.matches(passwordPattern);
    }
}