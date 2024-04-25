package com.keycloak.userstorage.provider;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;

import com.keycloak.userstorage.external.DbUtil;
import com.keycloak.userstorage.user.ExternalUser;
import com.keycloak.userstorage.user.UserAdapter;

import lombok.extern.slf4j.Slf4j;

/** create by clubbboy@naver.com
 * 
 */
@Slf4j
public class ExternalUserStorageProvider implements UserStorageProvider, UserLookupProvider, UserQueryProvider,
													CredentialInputValidator  
{

	private KeycloakSession ksession;
	private ComponentModel model;
	protected Map<String, UserModel> loadedUsers = new HashMap<>();
	
    private static Integer LIMIT = 10;
    private static Integer OFFSET = 0;
	
    public ExternalUserStorageProvider(KeycloakSession session, ComponentModel model) {
    	this.ksession = session;
		this.model = model;
    }
    
    /**
	 * 이 메서드는 공급자를 초기화하는 동안 열었던 모든 리소스를 닫습니다. 공급자에서 사용한 연결, 진술 또는 기타 리소스를 해제해야 합니다.
	 * Keycloak은 더 이상 필요하지 않을 때 이 방법을 사용하여 공급자를 닫습니다.
	 */
	@Override
	public void close() {
		log.info("[USERSTORAGE] close()");
	}

	/**
	 * 이 방법은 외부 저장소에서 암호 또는 OTP와 같은 특정 자격 증명 유형을 지원하는지 확인합니다. 상점에서 자격 증명 유형을 지원하는 경우
	 * true를 반환하고 그렇지 않으면 false를 반환해야 합니다. Keycloak은 이 방법을 사용하여 사용자가 사용할 수 있는 자격 증명
	 * 유형을 결정합니다.
	 */
	@Override
	public boolean supportsCredentialType(String credentialType) {

		log.info("[USERSTORAGE] supportsCredentialType({})", credentialType);
		log.info("[USERSTORAGE] PasswordCredentialModel.TYPE.endsWith(credentialType) = {}", PasswordCredentialModel.TYPE.endsWith(credentialType));
		
		return PasswordCredentialModel.TYPE.endsWith(credentialType);
	}

	/**
	 * 이 메서드는 특정 사용자가 외부 저장소에서 특정 자격 증명 유형에 대해 구성되었는지 확인합니다. 사용자가 외부 저장소에 저장된 특정 유형의
	 * 자격 증명을 가지고 있으면 true를 반환하고 그렇지 않으면 false를 반환해야 합니다. Keycloak은 이 방법을 사용하여 사용자에게
	 * 구성된 자격 증명 유형을 결정합니다.
	 */
	@Override
	public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {

		log.info("[USERSTORAGE] isConfiguredFor(realm={},user={},credentialType={})", realm.getName(), user.getUsername(),
				credentialType);

		// In our case, password is the only type of credential, so we allways return
		// 'true' if
		// this is the credentialType
		return supportsCredentialType(credentialType);
	}

	/**
	 * 이 메서드는 암호 또는 OTP와 같은 특정 자격 증명 입력을 외부 저장소에 대해 유효성을 검사합니다. 자격 증명 입력이 지정된 사용자의
	 * 외부 저장소에 저장된 입력과 일치하면 true를 반환하고 그렇지 않으면 false를 반환해야 합니다. 키클로크는 이 방법을 사용하여 외부
	 * 저장소의 자격 증명을 사용하여 사용자를 인증합니다.
	 */
	@Override
	public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {

		log.info("[USERSTORAGE] isValid(realm={},user={},credentialInput.type={})"
				, realm.getName(), user.getUsername(),input.getType());

		if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) {
			return false;
		}

		String username      = StorageId.externalId(user.getId());
		String dbPwd         = GET_PWD(model, username);
		byte[] decodedBytes  = Base64.getDecoder().decode(dbPwd);
		String decodedString = new String(decodedBytes);
		
		log.info("[USERSTORAGE]isValid 변환된 dbPwd = {} / decodedString = {} / input.getChallengeResponse = {}"
				 ,dbPwd, decodedString , input.getChallengeResponse());
		
		if (decodedString.equals(input.getChallengeResponse())) 
		{
			log.info("[USERSTORAGE]isValid result: true");
			return true;
		}
		else 
		{
			log.info("[USERSTORAGE]isValid result: false");
			return false;
		}
	}


	/**
	 * 이 메서드는 외부 스토어에서 ID로 사용자를 검색합니다. 지정된 ID를 가진 사용자를 나타내는 UserModel 개체를 반환하거나 해당
	 * 사용자가 없는 경우 null로 반환해야 합니다. 키클로크는 이 방법을 사용하여 외부 스토어에서 ID로 사용자를 찾습니다.
	 */
	@Override
	public UserModel getUserById(RealmModel realm, String id) {
		log.info("[USERSTORAGE] getUserById({})", id);

//        return getUserByUsername(realm, StorageId.externalId(id));
		return findUser(realm, StorageId.externalId(id), "uid");
	}

	/**
	 * 이 메서드는 외부 스토어에서 사용자 이름으로 사용자를 검색합니다. 지정된 사용자 이름을 가진 사용자를 나타내는 UserModel 개체를
	 * 반환하거나 해당 사용자가 없는 경우 null로 반환해야 합니다. 키클로크는 이 방법을 사용하여 외부 스토어에서 사용자 이름으로 사용자를
	 * 찾습니다.
	 */
	@Override
	public UserModel getUserByUsername(RealmModel realm, String username) {
		log.info("[USERSTORAGE] getUserByUsername({})", username);

		return findUser(realm, username, "username");
	}

	/**
	 * 이 방법은 외부 스토어에서 이메일로 사용자를 검색합니다. 지정된 이메일로 사용자를 나타내는 UserModel 개체를 반환하거나 해당
	 * 사용자가 없는 경우 null로 반환해야 합니다. 키클로크는 이 방법을 사용하여 외부 스토어에서 이메일로 사용자를 찾습니다.
	 */
	@Override
	public UserModel getUserByEmail(RealmModel realm, String email) {
		log.info("[USERSTORAGE] getUserByEmail({})", email);
		return findUser(realm, email, "email");
	}

	private UserModel findUser(RealmModel realm, String identifier, String type) {
		UserModel adapter = loadedUsers.get(identifier);

		log.info("[USERSTORAGE] findUser user = {} ", identifier);
		if (adapter == null) {
			log.info("[USERSTORAGE] findUser adapter == null = {} ", identifier);
			adapter = FIND_USER(realm, identifier, type);
			loadedUsers.put(identifier, adapter);
			
		} else {
			log.debug("[USERSTORAGE] findUser Found user data for {} in loadedUsers.", identifier);
		}
		return adapter;
	}

	@Override
	public int getUsersCount(RealmModel realm) {
		log.info("[USERSTORAGE] getUsersCount: realm={}", realm.getName());

		return GET_USER_CNT();
	}

	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult,
			Integer maxResults) {
		log.info("[USERSTORAGE] searchForUserStream1: realm={}", realm.getName());

		return GET_USER_STREAM(realm,  search, firstResult, maxResults);
		
	}

	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult,
			Integer maxResults) {
		log.info("[USERSTORAGE] searchForUserStream2: realm={} , firstResult = {} , maxResults ={}", realm.getName() , firstResult , maxResults);

		return GET_USER_STREAM(realm,  params, firstResult, maxResults);
		
	}

	// UserQueryProvider implementation

	@Override
	public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult,
			Integer maxResults) {
		log.info("[USERSTORAGE getGroupMembersStream]");
		return Stream.empty();
	}

	@Override
	public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
		log.info("[USERSTORAGE searchForUserByUserAttributeStream]");
		return Stream.empty();
	}

	// ------------------- Implementation

//	@Override
//	public UserModel addUser(RealmModel realm, String username) {
//		log.info("[USERSTORAGE addUser]");
//		return null;
//	}
//
//	@Override
//	public boolean removeUser(RealmModel realm, UserModel user) {
//		log.info("[USERSTORAGE removeUser]");
//		return false;
//	}
	

	
	
	
	
	
	
	
	
	
	/*******************************************
	 ******************query start ************************* 
	 ******************************************* 
	 * */
	
	public  String GET_PWD(ComponentModel model , String userId) {
		log.info("[Querys > GET_PWD] userId = {}" , userId);
		
		try (Connection c = DbUtil.getConnection(model)) 
		{
			PreparedStatement st = c.prepareStatement("select password from users where username = ?");
			st.setString(1, userId);
			st.execute();
			ResultSet rs = st.getResultSet();
			if (rs.next()) {
				String pwd = rs.getString(1);
				
				return pwd;
			} else {
				return "";
			}
		} catch (SQLException ex) {
			log.error("[I 300] {}", ex.getMessage());
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}
	
	public  UserModel FIND_USER( RealmModel realm , String userId, String type ) {
		log.info("[Querys > FIND_USER] userId = {} / type = {}" , userId , type);
		
		try (Connection c = DbUtil.getConnection(model)) 
		{
			log.info("[Querys > FIND_USER] user = {} ", userId);
			
			String query = " select a.username  \n" 
					     + "      , a.email     \n" 
					     + "      , a.firstName \n" 
					     + "      , a.lastName  \n"
					     + "      , to_char(a.birthDate, 'yyyy-mm-dd') as birthDay  \n" 
					     + " from users a       \n" 
					     + " where a.username = '" + userId + "' \n";
			
			log.info("[Querys > FIND_USER] query = {}", query);
			PreparedStatement st = c.prepareStatement(query);
			st.execute();
			
			ResultSet rs = st.getResultSet();
			if (rs.next()) 
			{
				log.info("[Querys > FIND_USER] email = {} ", rs.getString(2));
				ExternalUser cUser = ExternalUser.builder()
								.username(userId)
								.email(rs.getString(2))
								.firstName(rs.getString(3))
								.lastName(rs.getString(4))
								.build();
				
				/*user role info */
				String subQuery = "select role_name from user_role where username = '" + userId + "'";
				log.info("[Querys > FIND_USER] subQuery = {} ", subQuery);
				PreparedStatement st1 = c.prepareStatement(subQuery);
				st1.execute();
				ResultSet rs1 = st1.getResultSet();
				List<String> roles = new ArrayList<>();
				while (rs1.next()) {
					roles.add(rs1.getString("role_name"));
				}
				cUser.setRoles(roles);
				

				log.info("[Querys > FIND_USER] ExternalUser.tostring= {}", cUser.toString());
				UserModel adapter = new UserAdapter(this.ksession, realm, this.model, cUser);
				return adapter;
			}
		} catch (SQLException ex) {
			log.error("[Querys > FIND_USER] exception {}", ex.getMessage());
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
		
		return null;
	}
	
	
	public  int GET_USER_CNT() {
		
		log.info("[Querys > GET_USER_CNT] " );
		try (Connection c = DbUtil.getConnection(this.model)) {
			Statement st = c.createStatement();
			st.execute("select count(*) from users");
			ResultSet rs = st.getResultSet();
			rs.next();
			return rs.getInt(1);
		} catch (SQLException ex) {
			log.error("[Querys > GET_USER_CNT] getUsersCount: error ={}", ex.getMessage());
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}
	
	
	public  Stream<UserModel> GET_USER_STREAM( RealmModel realm , 
			                                      String search, 
			                                      Integer firstResult,
			                                      Integer maxResults) {
		
		log.info("[Querys > GET_USER_STREAM1] " );
		
		try (Connection c = DbUtil.getConnection(model)) {
			PreparedStatement st = c.prepareStatement(" select username , email, firstName,lastName, to_char(birthDate, 'yyyy-mm-dd') as birthDay "
					+ " from users " + " where username like ? " + " order by username " + " limit ? offset ?");
			st.setString(1, search);
			st.setInt(2, maxResults);
			st.setInt(3, firstResult);
			st.execute();
			ResultSet rs = st.getResultSet();
			List<UserModel> users = getUsers(rs, realm);
			return users.stream();
		} catch (SQLException ex) {
			log.error("[Querys > GET_USER_STREAM1] : error ={}", ex.getMessage());
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}
	
	public  Stream<UserModel> GET_USER_STREAM(RealmModel realm , 
												  Map<String, String> params,
												  Integer offset,
												  Integer limit) {
		
		log.info("[Querys > GET_USER_STREAM2] OFFSET = {} / LIMIT = {} /             " ,OFFSET , LIMIT );
		log.info("[Querys > GET_USER_STREAM2] offset = {} / limit = {} /  params = {}" ,offset , limit ,params.toString());
		
		if(limit == null) {//limit
			limit = LIMIT;
		}else {
			LIMIT = limit;
		}
		
		if(offset == null) {//offset
			offset = OFFSET;
			OFFSET = OFFSET+LIMIT;
		}else {
			OFFSET = offset;
		}
		
		
		
		String searchText = params.get("keycloak.session.realm.users.query.search");
		String str = params.get("search");
		log.info("str = {} / searchText = {}",str , searchText);
		for(String key : params.keySet()) {
			log.info("key = {} / value = {}" , key , params.get(key));
		}
		String query = "";
		query += " select username                                            \n";
		query += "      , email                                               \n";
		query += "      , firstName                                           \n";
		query += "      , lastName                                            \n";
		query += "      , to_char(birthDate, 'yyyy-mm-dd') as birthDay        \n";
		query += " from   users                                               \n";
		query += " where  1=1                                                 \n";
		if(searchText != null && !searchText.equals("") && !searchText.trim().equals("*")) {                
		query += " and    username like concat('%','" + searchText + "' ,'%') \n";
	    }                                                                   
	    query += " order by username                                          \n";
		query += " limit  " + limit                                     +     "\n";
		query += " offset " + offset                                    +     "\n";
		
		log.info("[Querys > GET_USER_STREAM2] query = {}" ,query);       
		       
		try (Connection c = DbUtil.getConnection(model)) {
			PreparedStatement st = 
					c.prepareStatement(query);
//			st.setInt(1, maxResults);
//			st.setInt(2, firstResult);
			st.execute();
			ResultSet rs = st.getResultSet();
			List<UserModel> users = getUsers(rs, realm);
			return users.stream();
		} catch (SQLException ex) {
			log.error("[Querys > GET_USER_STREAM2] : error ={}", ex.getMessage());
			throw new RuntimeException("Database error:" + ex.getMessage(), ex);
		}
	}
	
	
	
	
	private  List<UserModel> getUsers(ResultSet rs, RealmModel realm ) {

		log.info("[Querys > getUsers]");

		List<UserModel> users = new ArrayList<>();
		try {
			while (rs.next()) {
				log.info("[Querys > getUsers] username = {}", rs.getString("username"));
				ExternalUser cUser = ExternalUser.builder()
												 .username (rs.getString("username"))
												 .email    (rs.getString("email"))
												 .firstName(rs.getString("firstName"))
												 .lastName (rs.getString("lastName"))
												 .build();

				log.info("[Querys > getUsers] cUser.toString = {}", cUser.toString());
				UserModel adapter = new UserAdapter(this.ksession, realm, this.model, cUser);

				users.add(adapter);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return users;
	}

	

	
}
