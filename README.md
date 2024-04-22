keycloak SPI 예제 - version 24.0.1

desc : keycloak을 인증서버로 사용할 경우 기존에 있는 user의 Role과 login 처리.
  기존에 있는 Database와 연동하여 user정보와 권한정보를 가져와 keycloak 로그인이 가능하게 함.
  
  해당 프로젝트를 jar파일로 생성후 providers폴더에 넣어주면 keycloak admin console ui에 외부연동 가능한  SPI가 나타남.
