package pro.quicksense.modules.service.impl;


import cn.hutool.core.util.ObjectUtil;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import pro.quicksense.modules.common.CommonConstant;
import pro.quicksense.modules.common.Result;
import pro.quicksense.modules.entity.User;
import pro.quicksense.modules.mapper.UserMapper;
import pro.quicksense.modules.service.ISysUserService;


import java.util.Date;


@Service
@Slf4j
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

    @Override
    public Result<String> checkUserIsEffective(User user) {
        Result<String> result = new Result<>();

        // The user does not exist
        if (ObjectUtil.isEmpty(user)) {
            result.setCode(500);
            result.setMsg("The user does not exist. Please sign up.");
            return result;
        }

        // The user account is frozen.
        if (CommonConstant.USER_STATUS_FROZEN.equals(user.getStatus())) {
            result.setCode(500);
            result.setMsg("The user account is frozen.");
            return result;
        }

        result.setCode(200);
        return result;
    }

    @Override
    public Result<?> saveUser(String username, String realName, String password, String email) {

        // Encrypt the password
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String encodedPassword = passwordEncoder.encode(password);

        User user = new User();
        user.setCreateTime(new Date());
        user.setUsername(username);
        user.setRealname(realName);
        user.setPassword(encodedPassword);
        user.setEmail(email);
        user.setStatus(CommonConstant.USER_STATUS_NORMAL);
        try {
            this.save(user);
            return Result.success();
        } catch (DataIntegrityViolationException e) {
            return Result.error(CommonConstant.BAD_REQUEST_CODE, "Username or email already exists");
        } catch (Exception e) {
            return Result.error(CommonConstant.INTERNAL_SERVER_ERROR_CODE, "An error occurred during registration");
        }
    }
}