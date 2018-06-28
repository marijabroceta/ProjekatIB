package ib.project.rest;

import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import ib.project.dto.UserDTO;
import ib.project.model.Authority;
import ib.project.model.User;
import ib.project.service.AuthorityService;
import ib.project.service.AuthorityServiceInterface;
import ib.project.service.UserService;
import ib.project.service.UserServiceInterface;

@RestController
@RequestMapping(value = "api/users")
public class UserController {

	@Autowired
	private UserServiceInterface userService;
	
	@Autowired
	private AuthorityServiceInterface authorityService;
	
	@GetMapping
	public List<User> getAll() {
        return this.userService.findAll();
    }

	
	@PostMapping(consumes="application/json")
	public ResponseEntity<UserDTO> saveUser(@RequestBody UserDTO userDTO) {
		User u = new User();
		Authority authority = authorityService.findByName("REGULAR");
		
		u.setEmail(userDTO.getEmail());
		u.setPassword(userDTO.getPassword());
		u.setActive(false);
		u.getUser_authorities().add(authority);
		
		u = userService.save(u);
		return new ResponseEntity<UserDTO>(new UserDTO(u),HttpStatus.OK);
	}
	
	
	
}
