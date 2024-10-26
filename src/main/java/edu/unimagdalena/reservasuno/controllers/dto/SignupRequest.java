package edu.unimagdalena.reservasuno.controllers.dto;

import edu.unimagdalena.reservasuno.entities.User;

import java.util.List;
import java.util.Set;

public record SignupRequest (String username, String password, String email, Set<String> roles){



}
