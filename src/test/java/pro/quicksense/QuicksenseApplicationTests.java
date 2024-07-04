package pro.quicksense;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import pro.quicksense.modules.entity.User;
import pro.quicksense.modules.util.CodeUtil;



import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class QuicksenseApplicationTests {
	@Test
	void contextLoads() {
	}

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private CodeUtil codeUtil;

	@Test
	public void testRegisterUser() throws Exception {

		when(codeUtil.verifyCode(anyString(), anyString(), anyString())).thenReturn(true);

		User user = new User();
		user.setUsername("testuser");
		user.setEmail("test@example.com");
		user.setPassword("Test@1234");
		user.setConfirmPassword("Test@1234");
		user.setRealname("123");
		user.setVerifyCode("123456");

		String userJson = new ObjectMapper().writeValueAsString(user);

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.post("/user/register")
						.contentType(MediaType.APPLICATION_JSON)
						.content(userJson))
				.andExpect(status().isOk())
				.andExpect(content().string("User registration successful"))
				.andReturn();
		MockHttpServletResponse response = result.getResponse();

		System.out.println(response.getContentAsString());
	}
}
