package pro.quicksense;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import pro.quicksense.modules.controller.UserController;
import pro.quicksense.modules.entity.EmailLoginRequest;
import pro.quicksense.modules.entity.LoginRequest;
import pro.quicksense.modules.entity.User;
import pro.quicksense.modules.service.UserService;
import pro.quicksense.modules.service.impl.UserServiceImpl;
import pro.quicksense.modules.util.CodeUtil;
import pro.quicksense.modules.util.EmailUtil;
import pro.quicksense.modules.util.JwtInterceptor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@SpringBootTest
class QuicksenseApplicationTests {

	@Mock
	private UserService userService;

	@Mock
	private EmailUtil emailUtil;

	@Mock
	private CodeUtil codeUtil;

	@Mock
	private JwtInterceptor jwtInterceptor;

	@InjectMocks
	private UserController userController;

	@InjectMocks
	private UserServiceImpl userServiceImpl;

	@BeforeEach
	void setUp() {
		MockitoAnnotations.openMocks(this);
	}

	@Test
	void contextLoads() {
	}

	@Test
	void testUserRegister() {
		User user = new User();
		user.setUsername("testuser");
		user.setEmail("test@example.com");
		user.setPassword("Password123!");
		user.setConfirmPassword("Password123!");
		user.setRealname("Test User");
		user.setVerifyCode("123456");

		when(userService.registerUser(any(User.class))).thenReturn(any(ResponseEntity.class));

		ResponseEntity<?> response = userController.userRegister(user);

		assertNotNull(response);
		verify(userService).registerUser(any(User.class));
	}

	@Test
	void testLogin() {
		LoginRequest loginRequest = new LoginRequest();
		loginRequest.setUsername("testuser");
		loginRequest.setPassword("Password123!");

		when(userService.login(any(LoginRequest.class))).thenReturn(any(ResponseEntity.class));

		ResponseEntity<?> response = userController.login(loginRequest);

		assertNotNull(response);
		verify(userService).login(any(LoginRequest.class));
	}

	@Test
	void testLoginByEmail() {
		EmailLoginRequest request = new EmailLoginRequest();
		request.setEmail("test@example.com");
		request.setVerifyCode("123456");

		when(userService.loginByEmail(any(EmailLoginRequest.class))).thenReturn(any(ResponseEntity.class));

		ResponseEntity<?> response = userController.loginByEmail(request);

		assertNotNull(response);
		verify(userService).loginByEmail(any(EmailLoginRequest.class));
	}

	@Test
	void testEditUser() {
		User user = new User();
		user.setId("1");
		user.setUsername("testuser");

		when(userService.editUser(any(User.class))).thenReturn(any(ResponseEntity.class));

		ResponseEntity<?> response = userController.edit(user);

		assertNotNull(response);
		verify(userService).editUser(any(User.class));
	}

	@Test
	void testGetUserInfo() {
		when(userService.getUserInfo(anyString())).thenReturn(any(ResponseEntity.class));

		ResponseEntity<?> response = userController.getUserInfo("1");

		assertNotNull(response);
		verify(userService).getUserInfo(anyString());
	}

	@Test
	void testSendEmail() {
		when(userService.sendEmail(anyString())).thenReturn(any(ResponseEntity.class));

		ResponseEntity<?> response = userController.sendEmail("test@example.com");

		assertNotNull(response);
		verify(userService).sendEmail(anyString());
	}

	@Test
	void testRegisterUserService() {
		User user = new User();
		user.setUsername("testuser");
		user.setEmail("test@example.com");
		user.setPassword("Password123!");
		user.setConfirmPassword("Password123!");
		user.setRealname("Test User");
		user.setVerifyCode("123456");

		when(codeUtil.verifyCode(anyString(), anyString(), anyString())).thenReturn(true);
		when(emailUtil.isInvalidEmail(anyString())).thenReturn(false);

		ResponseEntity<?> response = userServiceImpl.registerUser(user);

		assertNotNull(response);
		verify(codeUtil).verifyCode(anyString(), anyString(), anyString());
		verify(emailUtil).isInvalidEmail(anyString());
	}

	@Test
	void testLoginService() {
		LoginRequest loginRequest = new LoginRequest();
		loginRequest.setUsername("testuser");
		loginRequest.setPassword("Password123!");

		User user = new User();
		user.setUsername("testuser");
		user.setPassword("$2a$10$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"); // BCrypt hashed password
		user.setStatus(1);

		when(userServiceImpl.getOne(any())).thenReturn(user);
		when(jwtInterceptor.generateToken(any(User.class))).thenReturn("token");

		ResponseEntity<?> response = userServiceImpl.login(loginRequest);

		assertNotNull(response);
		verify(userServiceImpl).getOne(any());
		verify(jwtInterceptor).generateToken(any(User.class));
	}
}