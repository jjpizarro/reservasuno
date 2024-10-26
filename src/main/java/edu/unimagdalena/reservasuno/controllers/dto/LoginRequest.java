package edu.unimagdalena.reservasuno.controllers.dto;

import lombok.Data;


public record LoginRequest (
    String username,
    String password){
    
}
