package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/myggen/wwwauth/pkg/handlers"
)

var BuildTime = ""
var Version = ""

func init() {
	if BuildTime == "" {
		BuildTime = time.Now().UTC().Format("20060102T15:04Z")
	}
	if Version == "" {
		Version = "go run"
	}
}

func projecthome() string {
	if os.Getenv("PROJECT_HOME") != "" {
		return os.Getenv("PROJECT_HOME")
	}
	//return "/home/espen/projects/wwwauth"
	return os.Getenv("PWD")
}

var (
	//go:embed templates/**
	files        embed.FS
	templates    map[string]*template.Template
	templatesDir = "templates"

	AppRoot   = "auth"
	varDir    = projecthome() + "/var"
	dbDir     = "/" + varDir + "/db"
	dbFile    = dbDir + "/demo-userdb.db"
	validPath = regexp.MustCompile("^/(.*)/([a-zA-Z0-9]*)$")
)

func redirect(w http.ResponseWriter, r *http.Request) {
	if false {
		http.Redirect(w, r, "/"+AppRoot+"/login", http.StatusMovedPermanently)
	}
	http.Redirect(w, r, "/"+AppRoot+"/home", http.StatusMovedPermanently)

}

var noCacheHeaders = map[string]string{
	"Expires":         "Mon,11 Nov 2019 08:36:00 GMT",
	"Cache-Control":   "no-cache, private, max-age=0, no-store, must-revalidate",
	"Pragma":          "no-cache",
	"X-Accel-Expires": "0",
}

func cacheHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set our NoCache headers
		for k, v := range noCacheHeaders {
			w.Header().Set(k, v)
		}
		h.ServeHTTP(w, r)
	})
}

func checkvars() {
	if dbFile == "" {
		panic("DbFile not set")
	}
	if len(templates) == 0 {
		panic("Templates not set")
	}

	if AppRoot == "" {
		panic("appRoot not set ")
	}

}
func main() {

	handlers.Templates = templates
	handlers.DbFile = dbFile
	handlers.AppRoot = AppRoot
	handlers.Files = files
	handlers.TemplatesDir = templatesDir
	// Loading here because go:embed. Requires restart of server if templates are changed.
	err := handlers.LoadTemplates()
	if err != nil {
		panic(err)
	}

	//checkvars()

	handlers.SetAuthHandlers()

	http.HandleFunc("/"+AppRoot+"/favicon.ico", handlers.FaviconHandler)

	fshtml := http.FileServer(http.Dir(projecthome() + "/html"))
	http.Handle("/"+AppRoot+"/html/", cacheHandler(http.StripPrefix("/"+AppRoot+"/html", fshtml)))

	fscss := http.FileServer(http.Dir(projecthome() + "/css"))
	http.Handle("/"+AppRoot+"/css/", cacheHandler(http.StripPrefix("/"+AppRoot+"/css/", fscss)))

	fsimg := http.FileServer(http.Dir(projecthome() + "/img"))
	http.Handle("/"+AppRoot+"/img/", cacheHandler(http.StripPrefix("/"+AppRoot+"/img/", fsimg)))
	http.HandleFunc("/", redirect)

	log.Printf("Listening on port %d...", 3000)

	err = http.ListenAndServe(":3000", nil)
	if err != nil {
		log.Fatalf("No command: %v\n", err)
	}

}
