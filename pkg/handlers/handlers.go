package handlers

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/myggen/wwwauth/pkg/mails"
	"github.com/myggen/wwwauth/pkg/userrepo"
	"golang.org/x/crypto/bcrypt"
)

type PageInfo struct {
	AppRoot  string
	Errors   []string
	User     userrepo.User
	Info     []string
	InfoHtml template.HTML
	Title    string
	H1       string

	BuildTime string
	Version   string
	Any       []any
}

// Set by calling code
var Templates map[string]*template.Template

var DbFile string

// TODO Use this
var AppRoot string

var validPath = regexp.MustCompile("^/(.*)/([a-zA-Z0-9]*)$")
var Files embed.FS
var TemplatesDir string

func NewPageInfo() PageInfo {
	pi := PageInfo{}
	pi.AppRoot = AppRoot
	return pi
}
func LogoutHandler(w http.ResponseWriter, r *http.Request, title string) {
	repo, err := userrepo.NewUserRepositorySqlite(DbFile)
	if err != nil {
		log.Printf("Logouthandler: %v", err)
		return
	}

	c, err := r.Cookie("anyany.xyz_session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Redirect(w, r, "/"+AppRoot+" /login", http.StatusMovedPermanently)
			return
		} else {
			log.Printf("logout: %v", err)
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// remove the users session from the session map

	err = repo.DeleteSession(c.Value)
	if err != nil {
		log.Printf("repo.DeleteSession failed on db %s: %v", DbFile, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// We need to let the client know that the cookie is expired
	// In the response, we set the session token to an empty
	// value and set its expiry as the current time
	http.SetCookie(w, &http.Cookie{
		Name:    "anyany.xyz_session_token",
		Value:   "",
		Expires: time.Now().UTC().Add(-24 * time.Hour),
		Path:    "/",
	})
	log.Printf("logout")
	http.Redirect(w, r, "/"+AppRoot+"/login", http.StatusFound)

}

func ChangePasswordHandler(w http.ResponseWriter, r *http.Request, title string) {

	if r.Method == "GET" {
		t, ok := Templates["change_password.html"]
		if !ok {
			log.Printf("template %s not found", "change_password.html")
			return

		}
		t.Execute(w, nil)
	} else if r.Method == "POST" {
		t, ok := Templates["change_password.html"]
		if !ok {
			log.Printf("template %s not found", "change_password.html")
			return
		}
		pi := NewPageInfo()
		r.ParseForm()
		password := r.Form["password"][0]
		passwordRepeat := r.Form["password-repeat"][0]
		if password != passwordRepeat {
			log.Printf("Error Passwords dont match")
			pi.Errors = append(pi.Errors, "Passswords don't match")
			t.Execute(w, pi)
			return
		}

		token := r.URL.Query().Get("token")
		if token == "" {
			log.Printf("No token")
			pi.Errors = append(pi.Errors, "Oops! No token")
			t.Execute(w, pi)
			return

		}
		repo, err := userrepo.NewUserRepositorySqlite(DbFile)
		if err != nil {
			log.Printf("ForgotPasswordHandler: %v", err)
			return
		}
		req, err := repo.GetPasswordResetRequest(token)
		if err != nil {
			log.Printf("ForgotPasswordHandler: GetPasswordResetRequest %v", err)
			return
		}
		user, err := repo.GetByEmail(req.Email)
		if err != nil {
			log.Printf("ForgotPasswordHandler: No such user  %v", err)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(r.Form["password"][0]), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Signup failed: bcrypt.GenerateFromPassword %v", err)
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! %v", err))
			t.Execute(w, pi)
			return
		}

		user.Passwd = string(hashedPassword)
		err = repo.Update(user)
		if err != nil {
			log.Printf("ForgotPasswordHandler: Update(user):  %v", err)
			return
		}

		pi.H1 = "Password Changed"
		pi.Title = "Password Changed"
		tresp, ok := Templates["response.html"]
		if !ok {
			log.Printf("template %s not found", "change_password.html")
			return
		}

		message := fmt.Sprintf(`Ok password updated <a href="/%s"> Log in</a>`, AppRoot)
		pi.InfoHtml = template.HTML(message)

		tresp.Execute(w, pi)

	}

}
func ForgotPasswordHandler(w http.ResponseWriter, r *http.Request, title string) {
	log.Printf("ForgotPasswordHandler")
	t, ok := Templates["forgot_password.html"]
	if !ok {
		log.Printf("template %s not found", "forgot_password.html")
		return

	}
	if r.Method == "GET" {
		t.Execute(w, nil)
	} else if r.Method == "POST" {
		repo, err := userrepo.NewUserRepositorySqlite(DbFile)
		if err != nil {
			log.Printf("ForgotPasswordHandler: %v", err)
			return
		}

		pi := NewPageInfo()
		r.ParseForm()
		email := r.Form["email"][0]
		if !strings.Contains(email, "@") {
			pi.Errors = append(pi.Errors, fmt.Sprintf("ForgotPassword  %s is not a valid email address", email))
			t.Execute(w, pi)
			return
		}

		req, err := repo.CreatePasswordResetRequest(email, time.Now().UTC().Add(+96*time.Hour))
		if err != nil {
			log.Printf("Error ForgotPasswordHandler repo.CreatePasswordResetRequest: %v", err)
			pi.Errors = append(pi.Errors, "Oops . CreatePasswordResetRequest failed. Please try later")
			t.Execute(w, pi)
			return
		}

		fmt.Printf("Proto: %s, Req: %s %s\n", r.Proto, r.Host, r.URL.Path)
		proto := "https"
		if strings.Contains(r.Host, "localhost") {
			proto = "http"
		}

		msg := fmt.Sprintf(`Password Reset

		Hello!
		
		Please click the link below to reset password: 

		%s://%s/%s/change_password/?token=%s

		
		Thanks.
		A-Team

		`, proto, r.Host, AppRoot, req.Token)

		message := mails.Message{
			//From:    "zappa@anyany.xyz",
			To:      []string{email},
			Subject: "Password reset confirmation",
			Body:    msg,
			//Server:  "mail.privateemail.com",
			//Port:    465,
		}

		err = mails.SendMailNoTLS(message)
		if err != nil {
			pi.Errors = append(pi.Errors, "Oops! Confirmation mail sending failed. Please try later")
			log.Printf("mails.SendMail failed: %v", err)
			t.Execute(w, pi)
			return
		}

		tresp, ok := Templates["password_email_response.html"]
		if !ok {
			log.Printf("template %s not found", "password_email_response.html")
			pi.Errors = append(pi.Errors, "Oops! Template reading error. ")
			tresp.Execute(w, pi)
			return
		}
		tresp.Execute(w, pi)
	}

}
func LoginHandler(w http.ResponseWriter, r *http.Request, title string) {

	fmt.Println("LoginHandler: method:", r.Method) //get request method
	t, ok := Templates["login.html"]
	if !ok {
		log.Printf("template %s not found", "login.html")
		return
	}

	if r.Method == "GET" {
		pi := NewPageInfo()
		pi.User = userrepo.User{}
		t.Execute(w, pi)
		return
	} else if r.Method == "POST" { // login logic
		pi := NewPageInfo()
		pi.User = userrepo.User{}

		r.ParseForm()

		fmt.Println("username:", r.Form["username"])
		userOrEmail := r.Form["username"][0]
		pw := r.Form["password"][0]

		fmt.Printf("Proto: %s, Req: %s %s\n", r.Proto, r.Host, r.URL.Path)
		repo, err := userrepo.NewUserRepositorySqlite(DbFile)
		if err != nil {
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! userrepoNewUserRepositorySqlite(%s): %v", err, DbFile))
			t.Execute(w, pi)
			return
		}
		user, err := repo.GetByEmail(userOrEmail)
		if (err == nil && user == userrepo.User{}) { // Email not found . Try by username
			user, err = repo.GetByUserName(userOrEmail)
			if (err == nil && user == userrepo.User{}) {
				//s := template.HTML("<h1> your html here</h1>")
				//pi.InfoHtml = append(pi.InfoHtml, s)
				pi.Errors = append(pi.Errors, "Wrong username or password")
				w.WriteHeader(http.StatusUnauthorized)
				t.Execute(w, pi)
				return
			} else if err != nil {
				log.Printf("repo.GetByEmail2: %v", err)
			}

		} else if err != nil {
			log.Printf("repo.GetByEmail1: %v", err)
		}
		if err = bcrypt.CompareHashAndPassword([]byte(user.Passwd), []byte(pw)); err != nil {
			// If the two passwords don't match, return a 401 status
			w.WriteHeader(http.StatusUnauthorized)
			pi.Errors = append(pi.Errors, "Wrong username or password")
			t.Execute(w, pi)
			return
		}
		// Ok Set session cookie
		sess, err := repo.CreateSession(user.UserUUID)
		if err != nil {
			pi.Errors = append(pi.Errors, "Error createing session. Please try later")
			t.Execute(w, pi)
			return
		}
		log.Printf("Setting cookie ")
		http.SetCookie(w, &http.Cookie{
			Name:    "anyany.xyz_session_token",
			Value:   sess.Token,
			Expires: sess.ExpiryTime,
			Path:    "/",
		})
		log.Printf("LoginHandler redirect home")
		http.Redirect(w, r, "/"+AppRoot+"/home", http.StatusMovedPermanently)
	} // Else method not supported
}
func ConfirmHandler(w http.ResponseWriter, r *http.Request, title string) {
	if r.Method == "GET" {
		pi := NewPageInfo()
		pi.Title = "Account confirmation"
		pi.H1 = "Account confirmation"

		t, ok := Templates["response.html"]
		if !ok {
			log.Printf("template %s not found", "response.html")
			return
		}

		token := r.URL.Query().Get("token")

		if token == "" {
			pi.Info = append(pi.Errors, "Oops . An error ocurred. Please try later")
			log.Printf("Error confirmHandler: token param empty \n")
			t.Execute(w, pi)
			return
		}

		repo, err := userrepo.NewUserRepositorySqlite(DbFile)
		if err != nil {
			pi.Info = append(pi.Errors, "Oops . An error ocurred during ConfirmEmail. Please try later")
			log.Printf("Error confirmHandler: %v\n", err)
			t.Execute(w, pi)
			return
		}
		err = repo.ConfirmEmail(token)
		if err != nil {
			log.Printf("Error confirmHandler: %v\n", err)
			pi.Info = append(pi.Errors, "Oops . An error ocurred during ConfirmEmail. Please try later")
			t.Execute(w, pi)
			return
		}

		log.Printf("Confirming Account")
		t, ok = Templates["confirmed_response.html"]
		if !ok {
			log.Printf("template %s not found", "confirmed_response.html")
			pi.Info = append(pi.Errors, "Oops . An error ocurred during ConfirmEmail. Please try later")
			t.Execute(w, pi)
			return
		}
		t.Execute(w, pi)
	}
}

func IsLoggedIn(r *http.Request) (userrepo.User, error) {
	repo, err := userrepo.NewUserRepositorySqlite(DbFile)
	if err != nil {
		return userrepo.User{}, err
	}
	c, err := r.Cookie("anyany.xyz_session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			return userrepo.User{}, nil
		} else {
			return userrepo.User{}, err
		}
	}
	session, err := repo.GetSession(c.Value)
	if err != nil {
		return userrepo.User{}, err
	}
	if (session == userrepo.Session{}) { //Session does not exist
		return userrepo.User{}, nil
	}

	user, err := repo.GetByUUID(session.UserUUID)
	if err != nil {

		return userrepo.User{}, err

	}
	return user, nil
}

var noCacheHeaders = map[string]string{
	"Expires":         "Mon,11 Nov 2019 08:36:00 GMT",
	"Cache-Control":   "no-cache, private, max-age=0, no-store, must-revalidate",
	"Pragma":          "no-cache",
	"X-Accel-Expires": "0",
}

func LoadTemplates() error {
	if Templates == nil {
		Templates = make(map[string]*template.Template)
	}
	tmplFiles, err := fs.ReadDir(Files, TemplatesDir)
	if err != nil {
		return err
	}

	for _, tmpl := range tmplFiles {
		if tmpl.IsDir() {
			continue
		}

		pt, err := template.ParseFS(Files, TemplatesDir+"/"+tmpl.Name())
		if err != nil {
			return err
		}
		Templates[tmpl.Name()] = pt
	}
	return nil
}

func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set our NoCache headers
		for k, v := range noCacheHeaders {
			w.Header().Set(k, v)
		}
		m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			log.Printf("Not found: %s\n", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		fn(w, r, m[2])
	}
}

func SetAuthHandlers() {
	fmt.Println(reflect.TypeOf(userrepo.User{}).PkgPath())
	//fmt.Println(reflect.TypeOf(lmath.Vec3{0, 0, 0}).PkgPath())

	http.HandleFunc("/"+AppRoot+"/login/", makeHandler(LoginHandler))
	http.HandleFunc("/"+AppRoot+"/logout/", makeHandler(LogoutHandler))
	http.HandleFunc("/"+AppRoot+"/forgot_password/", makeHandler(ForgotPasswordHandler))
	http.HandleFunc("/"+AppRoot+"/change_password/", makeHandler(ChangePasswordHandler))
	http.HandleFunc("/"+AppRoot+"/signup/", makeHandler(SignupHandler))
	http.HandleFunc("/"+AppRoot+"/confirm/", makeHandler(ConfirmHandler))
	http.HandleFunc("/"+AppRoot+"/home/", makeHandler(HomeHandler))

}
func HomeHandler(w http.ResponseWriter, r *http.Request, title string) {

	pi := NewPageInfo()
	pi.Title = "Road Labels"
	pi.H1 = "Demo Label App"
	if r.Method == "GET" {
		t, ok := Templates["home.html"]
		if !ok {
			log.Printf("template %s not found", "home.html")
			return
		}

		uu, err := IsLoggedIn(r)
		if err != nil {
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! handlers.IsLoggedIn(): %v", err))
			t.Execute(w, pi)
			return

		}

		if (uu == userrepo.User{}) {
			log.Printf("HomeHandler: Cookie anyany.xyz_session_token does not exist ")
			http.Redirect(w, r, "/"+AppRoot+"/login", http.StatusFound)
			return

		}

		pi.User = uu
		pi.Info = append(pi.Info, "Welcome")
		t.Execute(w, pi)
	}
}
func SignupHandler(w http.ResponseWriter, r *http.Request, title string) {

	pi := NewPageInfo()
	pi.User = userrepo.User{}

	t, ok := Templates["signup.html"]
	if !ok {
		log.Printf("template %s not found", "signup.html")
		return
	}
	tSignupResp, ok := Templates["signup_response.html"]
	if !ok {
		log.Printf("template %s not found", "signup_response.html")
		return
	}
	if r.Method == "GET" {
		t.Execute(w, pi)
		return
	} else {
		err := r.ParseForm()
		if err != nil {
			log.Fatalf("signupHandler : ParseForm: %v\n", err)
		}

		pi.User.Email = r.Form["email"][0]
		pi.User.UserName = r.Form["account_name"][0]

		if !strings.Contains(pi.User.Email, "@") {
			pi.Errors = append(pi.Errors, fmt.Sprintf("%s is not a valid email address", pi.User.Email))
			t.Execute(w, pi)
			return
		}

		password := r.Form["password"][0]
		passwordRepeat := r.Form["password-repeat"][0]
		if password != passwordRepeat {
			log.Printf("Error Passwords dont match")
			pi.Errors = append(pi.Errors, "Oops! Passswords don't match")
			t.Execute(w, pi)
			return
		}

		// A bcrypt cost of 6 means 64 rounds (2^6 = 64)
		// By increasing the cost, you can make the hash more difficult to compute.
		// The higher the cost, the longer the time needed to create the hash.
		// (this value can be more or less, depending on the computing power you wish to utilize)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(r.Form["password"][0]), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Signup failed: bcrypt.GenerateFromPassword %v", err)
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! %v", err))
			t.Execute(w, pi)
			return
		}

		pi.User.Passwd = string(hashedPassword)

		fmt.Printf("Proto: %s, Req: %s %s\n", r.Proto, r.Host, r.URL.Path)
		repo, err := userrepo.NewUserRepositorySqlite(DbFile)
		if err != nil {
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! userrepo: %v", err))
			t.Execute(w, pi)
			return
		}

		// Check that email does not exist in db
		u, err := repo.GetByEmail(pi.User.Email)
		if err != nil {
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! userrepo: %v", err))
			t.Execute(w, pi)
			return

		}
		if (u != userrepo.User{}) {
			pi.Errors = append(pi.Errors, "Email already exist")
			t.Execute(w, pi)
			return
		}

		// Check that userName does not exist in db
		u, err = repo.GetByUserName(pi.User.UserName)
		if err != nil {
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! userrepo: %v", err))
			t.Execute(w, pi)
			return

		}
		if (u != userrepo.User{}) {
			pi.Errors = append(pi.Errors, "UserName already exist")
			t.Execute(w, pi)
			return
		}

		// Set active = false untile confirmed
		pi.User.Active = false

		expire := time.Now().UTC().Add(24 * time.Hour)
		confirmation, err := repo.CreateEmailConfirmation(pi.User.Email, expire)
		if err != nil {
			log.Printf("Oops! userrepo.CreateEmailConfirmation %v", err)
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! Error during account creation: %v", err))
			t.Execute(w, pi)

			return
		}

		fmt.Printf("Proto: %s, Req: %s %s\n", r.Proto, r.Host, r.URL.Path)
		proto := "https"
		if strings.Contains(r.Host, "localhost") {
			proto = "http"
		}
		msg := fmt.Sprintf(`Account Signup

		Hello!
		
		We sent you this email because you're signing up for a new account with %s. Click the link below to complete registration %s://%s/%s/confirm/?token=%s
		
		Thanks.
		A-Team

		`, pi.User.Email, proto, r.Host, AppRoot, confirmation.Token)

		message := mails.Message{
			//From:    "any@anyany.xyz",
			To:      []string{pi.User.Email},
			Subject: "New account confirmation",
			Body:    msg,
			//Server:  "mail.privateemail.com",
			//Port:    465,
		}

		err = mails.SendMailNoTLS(message)
		if err != nil {
			pi.Errors = append(pi.Errors, "Oops! Confirmation mail sending failed. Please try later")
			log.Printf("mails.SendMailNoTLS failed: %v", err)
			t.Execute(w, pi)
			return
		}
		// Create user
		uuid, err := uuid.NewRandom()
		if err != nil {
			log.Printf("Oops! userrepo.Create %v", err)
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! userrepo.Create: %v", err))
			t.Execute(w, pi)

			return
		}

		pi.User.UserUUID = uuid.String()
		err = repo.Create(pi.User)
		if err != nil {
			log.Printf("Oops! userrepo.Create %v", err)
			pi.Errors = append(pi.Errors, fmt.Sprintf("Oops! userrepo.Create: %v", err))
			t.Execute(w, pi)

			return
		}

		tSignupResp.Execute(w, pi)
	}
}

func FaviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "img/helmet.ico")
}
