package pro.quicksense.modules.service;

import com.baomidou.mybatisplus.extension.service.IService;
import pro.quicksense.modules.common.Result;
import pro.quicksense.modules.entity.User;


public interface UserService extends IService<User> {
    Result<?> checkUserIsEffective(User user);

    Result<?> saveUser(String username, String realName, String password, String email);
}