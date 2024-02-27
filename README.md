# Password Leak Check

## 📖 Description
This project is a Python script that allows you to check if a password has been compromised in data breaches. It utilizes the Pwned Passwords API to perform this verification by comparing password hashes against a database of leaked passwords.

 
## 🛠️ Features
- Passwords Check: Checks if provided passwords has been compromised.
- Batch Check: Checks multiple passwords provided in a file and reports if any have been compromised.
- Save Results Option: The results of the checks can be saved to a text file for future reference.


## 📡 Technologies Used
![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white&style=for-the-badge)


## 💻 Usage

First of all, make sure you have Git installed.  


You will need to clone this repository to your local machine:

```
git clone https://github.com/pedrody/PasswordLeakCheck.git
```

Then navigate to the cloned repository:

```
cd PasswordLeakCheck
```

Now you're ready to use the script!


You can execute it from the command line, providing the following arguments:

```
[passwords]: Passwords to be verified

-f, --file: Checks passwords listed in a file.

-sF, --save-file: Saves the results to a text file.
```

### Example Usage

```
python main.py [PASSWORDS]

python main.py -f PASSWORD_LIST_HERE.txt

python main.py -f PASSWORD_LIST_HERE.txt -sF "WHERE YOU WANT TO SAFE THE OUTPUT FILE"
```
