# Overview of the Service

VulnPortal is a simple vulnerable web service designed for educational purposes in the field of cyber security. It features many of the OWASP Top 10 vulnerabilities, where users may exploit to test different penetration testing techniques. The web service was created using Flask (Python library) for the back end, and basic HTML and CSS for the front end.

**WARNING: This is for educational purposes only - do not employ penetration testing techniques on real websites without authorization.**

**WARNING: This is the version where many of the initial vulnerabilities have been patched, so hacking may be more challenging.**

# Prerequisites
Make sure you have docker installed beforehand on your machine. 

# How to run the application 

## 1. Clone the repository: 

```
git clone https://github.com/zdiegyang/VulnerablePortal.git
cd yourrepository
```

## 2. Build the docker image: 

```
docker build -t vulnerable-service .
```

## 3. Run the docker image: 

```
docker run -d -p 5000:5000 --name vulnerable-service-container vulnerable-service
```

## 4. Access the application: 
Open your web browser and navigate to http://localhost:5000 to access the application.

