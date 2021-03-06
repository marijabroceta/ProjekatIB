package ib.project.service;



import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import ib.project.model.User;
import ib.project.repository.UserRepository;

@Service
public class UserService implements UserServiceInterface{

	
	@Autowired
	private UserRepository userRepository;
	

	@Override
	public User findById(Long id) {
		User user = userRepository.findOne(id);
		return user;
	}

	@Override
	public User findByEmail(String email) {
		User user = userRepository.findByEmail(email);
		return user;
	}

	@Override
	public List<User> findAll() {
		List<User> users = userRepository.findAll();
		return users;
	}

	@Override
	public User save(User user) {
		return userRepository.save(user);
	}

	@Override
	public List<User> findAllByEmail(String email) {
		List<User> users = userRepository.findAllByEmail(email);
		return users;
	}

	@Override
	public List<User> findByActiveTrue() {
		List<User> users = userRepository.findByActiveTrue();
		return users;
	}
	
	
}
