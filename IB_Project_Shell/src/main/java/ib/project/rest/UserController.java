package ib.project.rest;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
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
@RequestMapping(value = "api/users", produces = MediaType.APPLICATION_JSON_VALUE)
@CrossOrigin("*")
public class UserController {

	@Autowired
	private UserServiceInterface userService;
	
	@Autowired
	private AuthorityServiceInterface authorityService;
	
	 @Autowired
	 PasswordEncoder passwordEncoder;
	
	@GetMapping
	public List<User> getAll() {
        return this.userService.findAll();
    }
	
	@RequestMapping("/logged")
    //@PreAuthorize("hasRole('REGULAR')")
    public User user(Principal user) {
        return this.userService.findByEmail(user.getName());
    }

	@GetMapping(value="/inactive")
	public ResponseEntity<List<UserDTO>>getInactive(){
		List<UserDTO> inactive = new ArrayList<>();
		List<User> users = userService.findAll();
		for (User user : users) {
			if(user.isActive() == false)
				inactive.add(new UserDTO(user));
		}
		return new ResponseEntity<List<UserDTO>>(inactive,HttpStatus.OK);
	}
	
	
	@GetMapping(value="/active")
	public List<User> getActive(){
		return this.userService.findByActiveTrue();
	}
	
	
	@GetMapping(value="/search/{email:.+}")
	public List<User> search(@PathVariable("email") String email){
		return this.userService.findAllByEmail(email); 
	}
	
	@PostMapping(value="/save",consumes="application/json")
	public ResponseEntity<UserDTO> saveUser(@RequestBody UserDTO userDTO) {
		User u = new User();
		Authority authority = authorityService.findByName("REGULAR");
		
		u.setEmail(userDTO.getEmail());
		u.setPassword(passwordEncoder.encode(userDTO.getPassword()));
		u.setActive(false);
		u.getUser_authorities().add(authority);
		
		u = userService.save(u);
		return new ResponseEntity<UserDTO>(new UserDTO(u),HttpStatus.OK);
	}
	
	@PutMapping(value="/{id}",consumes="application/json")
	//@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<UserDTO> enableUser(@PathVariable("id") Long id){
		User user = userService.findById(id);
		if(user == null) {
			return new ResponseEntity<UserDTO>(HttpStatus.BAD_REQUEST);
		}
		user.setActive(true);
		user = userService.save(user);
		return new ResponseEntity<UserDTO>(new UserDTO(user),HttpStatus.OK);
	}
	
	
	
}
