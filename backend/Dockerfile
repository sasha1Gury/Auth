FROM  maven:latest as stage1
WORKDIR /app
COPY pom.xml /app
RUN mvn dependency:resolve
COPY . /app
RUN mvn clean
RUN mvn package

FROM openjdk:17 as final
COPY --from=stage1 /app/target/*.jar app.jar
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]