# Spring Microservices Shop Application

A **Spring Boot + Spring Cloud** e-commerce system built with microservices.

## 🏗 Architecture

* **Service Registry (Eureka, 8761)** – service discovery
* **API Gateway (8080)** – routes client requests
* **Auth Service (8081)** – authentication & authorization
* **Admin Service (8082)** – admin operations
* **Client Service (8083)** – customer operations

## 🔗 Repository

[Spring Microservices Shop Application](https://github.com/xanderbilla/spring-microservice)

## 🚀 Run Locally

```bash
git clone https://github.com/xanderbilla/spring-microservice
cd spring-microservice
mvn clean install (each service one by one)
```

Start in order:

1. Service Registry → 2. API Gateway → 3. Other services (`auth`, `admin`, `client`)

## 🌐 Access

* **Eureka Dashboard** → [http://localhost:8761](http://localhost:8761)
* **Gateway** → [http://localhost:8080](http://localhost:8080)
* Example: `http://localhost:8080/auth/info`

## 📖 Documentation Index

API details are in the [**Wiki**](https://github.com/xanderbilla/spring-microservice/wiki):

* [Auth Service](https://github.com/xanderbilla/spring-microservice/wiki/Auth-Service)
* [Admin Service](https://github.com/xanderbilla/spring-microservice/wiki)
* [Client Service](https://github.com/xanderbilla/spring-microservice/wiki)
* [API Gateway](https://github.com/xanderbilla/spring-microservice/wiki)
* [Service Registry](https://github.com/xanderbilla/spring-microservice/wiki)

## ⚙ Tech Stack

Spring Boot · Spring Cloud · Spring Cloud Gateway · Netflix Eureka · Maven · Java 17

## 🛠 Troubleshooting

* Service not in Eureka? → check `eureka.client.service-url.defaultZone`
* Gateway not routing? → confirm service registered in Eureka
* Port conflicts? → change `server.port` in `application.properties`

## 👥 Author

[Xander Billa](https://xanderbilla.com)
