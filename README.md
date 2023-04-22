# Open Redirect Lab

**Open Redirect Vulnerability Lab written in Flask.**

### Setup
> python3 and pip3 must be pre-installed.
```sh
git clone https://github.com/amir-h-fallahi/Open-Redirect-Lab/
cd Open-Redirect-Lab
pip3 install virtualenv
virtualenv env
source env/bin/activate # Linux, Mac
env\Scripts\activate # Windows
pip3 install -r requirements.txt
python3 app.py
```
- It's availabe on http://127.0.0.1:5000
- Also after running you can access it on http://local.securityflaws.net:5000/

![Screenshot from 2023-04-22 10-38-41](https://user-images.githubusercontent.com/63167700/233769020-1a2eb3c0-842d-4db8-94a7-c2b63e55b81b.png)

### Functions
#### Login
- http://127.0.0.1:5000/auth/login/
- Default credentials:
  - Username: `admin`
  - Password: `admin`
#### Dashboard
  - http://127.0.0.1:5000/dashboard/
  - After logging in you can access it.
  - 1 client side open redirect.
#### Checkout
- http://127.0.0.1:5000/checkout/
- 9 level of client side open redirect.
#### Redirect
- http://127.0.0.1:5000/redirect/
- 8 level of server side open redirect.
