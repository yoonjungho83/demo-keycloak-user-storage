package com.keycloak.userstorage.user;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class ExternalUser {
	
	
	private final String username;
    private final String email;
    private final String firstName;
    private final String lastName;
    private final String birthDay;
	private List<String> roles;
	
	public String toString() {
		
		return " username="  + username
			  +",email="     + email
			  +",firstName=" + firstName
			  +",lastName="  + lastName 
			  +",birthDay="  + birthDay
		      +",roles="     + (this.roles !=null ? this.roles.toString():"[]");
	}
	

}
