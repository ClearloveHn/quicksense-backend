package pro.quicksense.modules.controller;


import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pro.quicksense.modules.entity.EmailLoginRequest;
import pro.quicksense.modules.entity.LoginRequest;
import pro.quicksense.modules.entity.User;
import pro.quicksense.modules.service.UserService;


@Slf4j
@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> userRegister(@RequestBody User user) {
        return userService.registerUser(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest loginRequest) {
        return userService.login(loginRequest);
    }

    @PostMapping("/loginByEmail")
    public ResponseEntity<?> loginByEmail(@RequestBody @Valid EmailLoginRequest request) {
        return userService.loginByEmail(request);
    }

    @PostMapping("/edit")
    public ResponseEntity<?> edit(@RequestBody User user) {
        return userService.editUser(user);
    }

    @GetMapping("/userInfo")
    public ResponseEntity<?> getUserInfo(@RequestParam(value = "id", required = false) String id) {
        return userService.getUserInfo(id);
    }

    @GetMapping("/sendEmail")
    public ResponseEntity<?> sendEmail(@RequestParam(value = "email") String email) {
        return userService.sendEmail(email);
    }
}
