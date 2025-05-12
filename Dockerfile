FROM --platform=linux/amd64 openjdk:17-jdk-slim

# 1. 환경변수 파일 복사
COPY .env .env

# 2. 작업 디렉터리
WORKDIR /app

# 3. jar 파일 복사 (이름 명시적으로 지정!)
COPY build/libs/*.jar app.jar

# 4. 포트 오픈
EXPOSE 8888

# 5. 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "app.jar"]
