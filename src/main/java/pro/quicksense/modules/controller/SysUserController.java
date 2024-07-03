package pro.quicksense.modules.controller;


import cn.hutool.core.util.ObjectUtil;
import com.alibaba.fastjson.JSONObject;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import pro.quicksense.modules.common.CommonConstant;
import pro.quicksense.modules.common.Result;
import pro.quicksense.modules.entity.User;
import pro.quicksense.modules.service.ISysUserService;
import pro.quicksense.modules.util.CodeUtil;
import pro.quicksense.modules.util.EmailUtil;

import java.util.Date;
import java.util.List;
import java.util.Objects;


@Slf4j
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService UserService;

    @Autowired
    private EmailUtil emailUtil;

    @Autowired
    private CodeUtil codeUtil;

    @PostMapping("/register")
    public Result<?> userRegister(@RequestBody JSONObject jsonObject) {
        String username = jsonObject.getString("username");
        if (StringUtils.isBlank(username)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Username cannot be empty");
        }
        String email = jsonObject.getString("email");
        if (StringUtils.isBlank(email)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Email cannot be empty");
        }
        String password = jsonObject.getString("password");
        if (StringUtils.isBlank(password)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Password cannot be empty");
        }
        String confirmPassword = jsonObject.getString("confirmPassword");
        if (StringUtils.isBlank(confirmPassword)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Confirm password cannot be empty");
        }
        String realName = jsonObject.getString("realName");
        if (StringUtils.isBlank(realName)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Real name cannot be empty");
        }

        String verifyCode = jsonObject.getString("verifyCode");
        if (StringUtils.isBlank(verifyCode )) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "verifyCode  cannot be empty");
        }

        // Validate email address format
        if (emailUtil.isInvalidEmail(email)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Invalid email format");
        }

        // Validate password format
        String passwordPattern = "^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,20}$";
        if (!password.matches(passwordPattern)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Password must contain letters, numbers, and special characters");
        }

        // Check if password and confirm password are equal
        if (!password.equals(confirmPassword)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Password and confirm password do not match");
        }

        //Email verification
        if (!codeUtil.verifyCode(email,verifyCode,CommonConstant.KEY_PREFIX)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Verification code error");
        }

        return sysUserService.saveUser(username, realName, password, email);
    }


    @PostMapping("/login")
    public Result<?> login(@RequestBody JSONObject jsonObject) {
        Result<?> result = new Result<>();
        String username = jsonObject.getString("username");
        if (StringUtils.isBlank(username)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Username cannot be empty");
        }
        String password = jsonObject.getString("password");
        if (StringUtils.isBlank(password)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Password cannot be empty");
        }

        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUsername, username);
        User user = sysUserService.getOne(queryWrapper);

        // Check if the user exists and is effective
        result = sysUserService.checkUserIsEffective(user);
        if (!Objects.equals(result.getCode(), CommonConstant.SUCCESS_CODE)) {
            return result;
        }

        // Check if the username or password is correct
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        boolean matches = passwordEncoder.matches(password, user.getPassword());
        if (!matches) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Incorrect username or password");
        }

        // Login successful, generate token and return
        return userInfo(user);
    }

    @PostMapping("/loginByEmail")
    public Result<?> logout(@RequestBody JSONObject jsonObject) {
        String email = jsonObject.getString("email");
        String verifyCode = jsonObject.getString("verifyCode");
        if (StringUtils.isBlank(email)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Email cannot be empty");
        }
        if (StringUtils.isBlank(verifyCode)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "verifyCode  cannot be empty");
        }

        //Email verification
        if (!codeUtil.verifyCode(email,verifyCode,CommonConstant.KEY_PREFIX)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Verification code error");
        }

        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getEmail, email);
        User user = sysUserService.getOne(queryWrapper);
        if (ObjectUtil.isEmpty(user)) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "User not found");
        }
        return userInfo(user);

    }


    @PostMapping("/edit")
    public Result<Object> edit(@RequestBody User user) {
        try {
            user.setUpdateTime(new Date());
            sysUserService.updateById(user);
            return Result.success("edit success");
        } catch (Exception e) {
            return Result.error(CommonConstant.INTERNAL_SERVER_ERROR_CODE, "edit failed");
        }
    }

    @GetMapping("/userInfo")
    public Result<?> info(@RequestParam(value = "id", required = false) String id) {
        User user = new User();

        if (StringUtils.isNotBlank(id)) {
            user = sysUserService.getById(id);
        } else {
            List<User> userList = sysUserService.list();
            return Result.success(userList);
        }

        return Result.success("User info", user);
    }

    @PostMapping("/sendEmail")
    public Result<?> sendEmail(@RequestParam(value = "email") String email) {
        try {
            emailUtil.sendSimpleMail(email);
        } catch (Exception e) {
            return Result.error(CommonConstant.INTERNAL_SERVER_ERROR_CODE, "send email failed");
        }
        return Result.success("send email success");
    }

    private Result<?> userInfo(User user) {
        String token = generateToken(user);
        return Result.success(token);
    }

    private String generateToken(User user) {
        // Set token expiration time, here set to 1 day
        Date expiration = new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000);

        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("userId", user.getId())
                .setIssuedAt(new Date())
                .setExpiration(expiration)
                .signWith(SignatureAlgorithm.HS512, "secret")  // todo For testing only, please use a different secret key in production
                .compact();
    }
}
