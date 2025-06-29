package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

// Terminal colors
const (
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Reset  = "\033[0m"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"` // stored hash
	Salt     string `json:"salt"`     // stored salt
}

var dbPath = "files/db.json"

func main() {
	ensureDataDir()
	printBanner()

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print(Cyan, "\nroot@auth-sim> ", Reset)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "help":
			printHelp()
		case "1", "register":
			clientRegister(reader)
		case "2", "login":
			clientLogin(reader)
		case "3", "dump":
			serverShowData()
		case "4", "attack":
			attackerOfflineAttack()
        case "5", "credential":
            attackerCredentialStuffing()
        case "6", "rainbow":
            attackerRainbowTable()
        case "7", "saltexpose":
            attackerSaltExposure()
        case "8", "spraying":
            attackerPasswordSpraying()
        case "9", "online":
            attackerOnlineBruteForce()
		case "10", "exit", "quit":
			fmt.Println(Green + "👋 Exiting... Stay stealthy." + Reset)
			return
		default:
			fmt.Println(Red + "Invalid command. Type 'help' for options." + Reset)
		}
	}
}

func printBanner() {
	fmt.Println(Green + `
   _____            _       _   _        _   _             
  |_   _|          | |     | | | |      | | (_)            
    | |  _ __   ___| |_ ___| |_| | ___  | |_ _  ___  _ __  
    | | | '_ \ / _ \ __/ _ \ __| |/ _ \ | __| |/ _ \| '_ \ 
   _| |_| | | |  __/ ||  __/ |_| |  __/ | |_| | (_) | | | |
  |_____|_| |_|\___|\__\___|\__|_|\___|  \__|_|\___/|_| |_|

    Traditional Auth Simulator - Hacker Mode
` + Reset)
	fmt.Println(Yellow + "Type 'help' for commands. E.g. register, login, dump, attack, exit" + Reset)
}

func printHelp() {
    fmt.Println(Cyan + `
Available commands:
  1 or register    - Register a new user (client)
  2 or login       - Login as existing user (client)
  3 or dump        - Simulate DB breach and leak hashes
  4 or attack      - Run offline brute-force demo
  5 or credential  - Credential stuffing attack demo
  6 or rainbow     - Rainbow table attack demo
  7 or saltexpose  - Salt exposure attack demo
  8 or spraying    - Password spraying attack demo
  9 or online      - Online brute-force attack demo
  exit or quit     - Exit the simulator
` + Reset)
}


func ensureDataDir() {
	if _, err := os.Stat("files"); os.IsNotExist(err) {
		os.Mkdir("files", 0755)
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		os.WriteFile(dbPath, []byte("[]"), 0644)
	}
}

// === Client Registration ===
func clientRegister(reader *bufio.Reader) {
	fmt.Println(Yellow + "\n[Client] Initiating registration..." + Reset)

	fmt.Print(Cyan + "username: " + Reset)
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print(Cyan + "password: " + Reset)
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	fmt.Println(Yellow + "\n[Client] Transmitting credentials to server..." + Reset)
	fakeProgress("Encrypting payload", 700)
	serverRegister(username, password)
}

// === Server Registration ===
func serverRegister(username, password string) {
	fmt.Println(Green + "[Server] Received registration request." + Reset)

	fmt.Println(Green + "[Server] Generating cryptographically secure salt..." + Reset)
	fakeProgress("Generating salt", 500)
	salt, err := generateSalt(16)
	if err != nil {
		fmt.Println(Red+"[Server] ERROR generating salt:", err, Reset)
		return
	}
	fmt.Println(Green+"[Server] Salt (base64):", salt+Reset)

	fmt.Println(Green + "[Server] Hashing password+salt with bcrypt..." + Reset)
	fakeProgress("Hashing password", 1000)
	hashed, err := hashPassword(password, salt)
	if err != nil {
		fmt.Println(Red+"[Server] ERROR hashing password:", err, Reset)
		return
	}
	fmt.Println(Green + "[Server] Hashed password:", hashed + Reset)

	user := User{
		Username: username,
		Password: hashed,
		Salt:     salt,
	}

	err = saveUser(user)
	if err != nil {
		fmt.Println(Red+"[Server] ERROR saving user:", err, Reset)
		fmt.Println(Red + "[Server] Possible duplicate username." + Reset)
		return
	}
	fmt.Println(Green + "✅ [Server] Registration complete and saved to DB." + Reset)
}

// === Client Login ===
func clientLogin(reader *bufio.Reader) {
	fmt.Println(Yellow + "\n[Client] Initiating login..." + Reset)

	fmt.Print(Cyan + "username: " + Reset)
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print(Cyan + "password: " + Reset)
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	fmt.Println(Yellow + "\n[Client] Sending login request to server..." + Reset)
	fakeProgress("Transmitting credentials", 700)

	serverLogin(username, password)
}

// === Server Login ===
func serverLogin(username, password string) {
	fmt.Println(Green + "[Server] Received login request." + Reset)

	user := findUser(username)
	if user == nil {
		fmt.Println(Red + "[Server] User not found!" + Reset)
		return
	}

	fmt.Println(Green + "[Server] Retrieved salt from DB:", user.Salt + Reset)

	fmt.Println(Green + "[Server] Verifying password..." + Reset)
	fakeProgress("Checking password hash", 1000)

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password+user.Salt))
	if err != nil {
		fmt.Println(Red + "[Server] ❌ Password mismatch! Access denied." + Reset)
		return
	}
	fmt.Println(Green + "[Server] ✅ Password match! Access granted." + Reset)

	fmt.Println(Yellow + "\n⚠️  [Server] WARNING: Password processed in plaintext during login. Potential security risk!" + Reset)
}

// === Server DB Breach Simulation ===
func serverShowData() {
	fmt.Println(Red + "\n!!! ALERT: DATABASE BREACH SIMULATION !!!" + Reset)

	users := loadUsers()
	if len(users) == 0 {
		fmt.Println(Yellow + "[Server] DB empty. No data to leak." + Reset)
		return
	}

	for i, u := range users {
		fmt.Printf("\n%sUser #%d%s\n", Cyan, i+1, Reset)
		fmt.Println(Cyan+"Username: "+Reset, u.Username)
		fmt.Println(Cyan+"Salt (Base64): "+Reset, u.Salt)
		fmt.Println(Cyan+"Password Hash: "+Reset, u.Password)
	}

	fmt.Println(Red + "\n!!! ATTACKER GOT FULL ACCESS TO HASHES AND SALTS !!!" + Reset)
}

// === Attacker Offline Brute Force ===
func attackerOfflineAttack() {
	fmt.Println(Red + "\n[Attacker] Launching offline brute force attack..." + Reset)

	users := loadUsers()
	if len(users) == 0 {
		fmt.Println(Yellow + "[Attacker] No users found. Aborting attack." + Reset)
		return
	}

	file, err := os.Open("files/passwords.txt")
	if err != nil {
		fmt.Println(Red+"[Attacker] ERROR loading dictionary:", err, Reset)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	guesses := []string{}
	for scanner.Scan() {
		guesses = append(guesses, strings.TrimSpace(scanner.Text()))
	}

	for _, user := range users {
		fmt.Printf("\n%s[Attacker] Targeting user: %s%s\n", Yellow, user.Username, Reset)
		start := time.Now()
		cracked := false
		for _, guess := range guesses {
			fakeProgress(fmt.Sprintf("Trying password: %s", guess), 200)
			if verifyPassword(guess, user.Salt, user.Password) {
				fmt.Printf(Green+"[Attacker] 💥 Password cracked! It's: %s%s\n", guess, Reset)
				cracked = true
				break
			}
		}
		if !cracked {
			fmt.Println(Red + "[Attacker] ❌ Failed to crack password with dictionary." + Reset)
		}
		fmt.Printf(Cyan+"[Attacker] Time taken: %v\n"+Reset, time.Since(start))
	}

	fmt.Println(Red + "\n[Attacker] Attack simulation complete." + Reset)
}

// === Helper functions ===

func fakeProgress(action string, ms int) {
	fmt.Print(Cyan + action + " ")
	for i := 0; i < 3; i++ {
		time.Sleep(time.Duration(ms) * time.Millisecond / 3)
		fmt.Print(".")
	}
	fmt.Println(Reset)
}

func generateSalt(size int) (string, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func hashPassword(password, salt string) (string, error) {
	combined := password + salt
	hashed, err := bcrypt.GenerateFromPassword([]byte(combined), bcrypt.DefaultCost)
	return string(hashed), err
}

func verifyPassword(password, salt, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password+salt))
	return err == nil
}

func saveUser(user User) error {
	users := loadUsers()
	for _, u := range users {
		if u.Username == user.Username {
			return fmt.Errorf("username already exists")
		}
	}
	users = append(users, user)
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dbPath, data, 0644)
}

func loadUsers() []User {
	users := []User{}
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return users
	}
	json.Unmarshal(data, &users)
	return users
}

func findUser(username string) *User {
	users := loadUsers()
	for _, u := range users {
		if u.Username == username {
			return &u
		}
	}
	return nil
}

// --- 5. Credential Stuffing ---
func attackerCredentialStuffing() {
    fmt.Println(Red + "\n[Attacker] Credential Stuffing Attack Started..." + Reset)

    leakedCreds := loadLeakedCreds()
    users := loadUsers()

    for _, lc := range leakedCreds {
        for _, u := range users {
            if lc.Username == u.Username {
                fmt.Printf(Yellow+"Trying leaked credential for user %s: %s\n"+Reset, u.Username, lc.Password)
                if verifyPassword(lc.Password, u.Salt, u.Password) {
                    fmt.Println(Green + "💥 Credential stuffing SUCCESS: Password found!" + Reset)
                } else {
                    fmt.Println(Red + "Credential stuffing failed for this password." + Reset)
                }
            }
        }
    }
}

// --- 6. Rainbow Table Attack (Simulated) ---
func attackerRainbowTable() {
    fmt.Println(Red + "\n[Attacker] Rainbow Table Attack Started (Simulated)..." + Reset)

    rainbow := loadRainbowTable()
    users := loadUsers()

    for _, u := range users {
        fmt.Printf(Yellow+"Target user: %s\n"+Reset, u.Username)
        cracked := false
        for pw, hash := range rainbow {
            // Normally rainbow tables are for unsalted hashes,
            // here we simulate failure because salt is present.
            if pw == "password123" { // Just a demo condition
                fmt.Println(Red + "Failed due to salt protection." + Reset)
                cracked = false
                break
            }
            _ = hash
        }
        if !cracked {
            fmt.Println(Green + "Rainbow table attack failed due to salt." + Reset)
        }
    }
}

// --- 7. Salt Exposure Attack (Demo) ---
func attackerSaltExposure() {
    fmt.Println(Red + "\n[Attacker] Salt Exposure Attack Started..." + Reset)
    users := loadUsers()
    guesses := loadPasswords()

    for _, u := range users {
        fmt.Printf(Yellow+"Target user: %s\n"+Reset, u.Username)
        fmt.Println(Cyan+"Known salt (Base64): " + u.Salt + Reset)

        cracked := false
        for _, guess := range guesses {
            combined := guess + u.Salt
            hashedGuess, _ := bcrypt.GenerateFromPassword([]byte(combined), bcrypt.DefaultCost)
            fmt.Printf(Cyan+"Trying guess '%s' + salt, hash: %s\n"+Reset, guess, string(hashedGuess))
            if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(guess+u.Salt)) == nil {
                fmt.Println(Green + "💥 Cracked password using known salt: " + guess + Reset)
                cracked = true
                break
            }
        }
        if !cracked {
            fmt.Println(Red + "Failed to crack password even with salt knowledge." + Reset)
        }
    }
}

// --- 8. Password Spraying ---
func attackerPasswordSpraying() {
    fmt.Println(Red + "\n[Attacker] Password Spraying Attack Started..." + Reset)
    users := loadUsers()
    commonPasswords := []string{"123456", "password", "Password1", "qwerty", "admin"}

    for _, pwd := range commonPasswords {
        fmt.Printf(Cyan+"Trying common password '%s' on all users...\n"+Reset, pwd)
        for _, u := range users {
            err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pwd+u.Salt))
            if err == nil {
                fmt.Printf(Green+"💥 Password spraying SUCCESS: User '%s' password is '%s'\n"+Reset, u.Username, pwd)
            }
        }
    }
}

// --- 9. Online Brute Force Attack (Simulated) ---
func attackerOnlineBruteForce() {
    fmt.Println(Red + "\n[Attacker] Online Brute Force Attack Started (Simulated)..." + Reset)
    users := loadUsers()
    guesses := loadPasswords()

    for _, u := range users {
        fmt.Printf(Yellow+"Target user: %s\n"+Reset, u.Username)
        attempts := 0
        for _, guess := range guesses {
            fmt.Printf(Cyan+"Trying password '%s'... \n"+Reset, guess)
            attempts++
            if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(guess+u.Salt)) == nil {
                fmt.Println(Green + "💥 Password cracked online: " + guess + Reset)
                break
            }
            if attempts >= 5 {
                fmt.Println(Red + "❌ Account locked due to too many failed attempts." + Reset)
                break
            }
            time.Sleep(500 * time.Millisecond) // simulate delay and throttling
        }
    }
}

type leakedCredential struct {
    Username string
    Password string
}

func loadLeakedCreds() []leakedCredential {
    var creds []leakedCredential
    file, err := os.Open("files/leaked_creds.txt")
    if err != nil {
        fmt.Println(Red + "Error loading leaked creds file." + Reset)
        return creds
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        parts := strings.Split(line, ":")
        if len(parts) == 2 {
            creds = append(creds, leakedCredential{Username: parts[0], Password: parts[1]})
        }
    }
    return creds
}

func loadRainbowTable() map[string]string {
    rainbow := make(map[string]string)
    file, err := os.Open("files/rainbow_table.txt")
    if err != nil {
        fmt.Println(Red + "Error loading rainbow table file." + Reset)
        return rainbow
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        parts := strings.Split(line, ":")
        if len(parts) == 2 {
            rainbow[parts[0]] = parts[1]
        }
    }
    return rainbow
}

func loadPasswords() []string {
    data, err := os.ReadFile("files/passwords.txt")
    if err != nil {
        fmt.Println(Red + "Error loading password dictionary." + Reset)
        return []string{}
    }
    lines := strings.Split(string(data), "\n")
    passwords := []string{}
    for _, line := range lines {
        pw := strings.TrimSpace(line)
        if pw != "" {
            passwords = append(passwords, pw)
        }
    }
    return passwords
}

