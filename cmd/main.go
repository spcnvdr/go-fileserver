/*
Simple HTTP/S file server, defaults to serving on port 8080. Allows file
upload, download, and deletion. Folders can be deleted if empty.
Run with --help for full options
*/
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const Version = "mini server 0.0.8"

/*
File: a small struct to hold information about a file that can be easily
displayed in templates
*/
type File struct {
	Name  string
	Size  string
	Mode  string
	Date  string
	IsDir bool
}

/* Files is a slice holding information about each file in the destination
directory */
type Files []File

/*
Context is the struct containing all data passed to the template
*/
type Context struct {
	Title     string
	Directory string // Current directory user is in
	Parent    string // The parent directory
	Files     Files
}

// global variables for command line arguments
var (
	AUTH      bool
	CERT      string
	HOST      string
	KEY       string
	PASS      string
	PORT      string
	TLS       bool
	USER      string
	VERBOSE   bool
	VERSION   bool
	FILE_PATH string // folder to serve files from
)

// init is automatically called at start, setup cmd line args
func init() {

	// host/IP adddress
	flag.StringVar(&HOST, "ip", "0.0.0.0", "IP address to serve on, defaults to 0.0.0.0")
	flag.StringVar(&HOST, "i", "0.0.0.0", "IP shortcut")

	// version
	flag.BoolVar(&VERSION, "version", false, "Print program version")
	flag.BoolVar(&VERSION, "V", false, "Version shortcut")

	// port
	flag.StringVar(&PORT, "port", "8080", "Port to listen on, defaults to 8080")
	flag.StringVar(&PORT, "p", "8080", "Port shortcut")

	// enable TLS
	flag.BoolVar(&TLS, "tls", false, "Generate and use self-signed TLS cert")
	flag.BoolVar(&TLS, "t", false, "TLS shortcut")

	// Use custom TLS key
	flag.StringVar(&KEY, "key", "", "Use custom TLS Key, must also provide cert in PEM")
	flag.StringVar(&KEY, "k", "", "TLS key shortcut")

	// Use custom TLS cert
	flag.StringVar(&CERT, "cert", "", "Use custom TLS Cert, must also provide key")
	flag.StringVar(&CERT, "c", "", "TLS cert shortcut")

	// enable simple authentication
	flag.StringVar(&USER, "user", "", "Enable authentication with this username")
	flag.StringVar(&USER, "u", "", "Basic auth shortcut")

	// enable verbose mode
	flag.BoolVar(&VERBOSE, "verbose", false, "Enable verbose output")
	flag.BoolVar(&VERBOSE, "v", false, "Verbose shortcut")
}

func main() {
	// setup and parse command line arguments
	var cert, key string
	flag.Usage = printHelp
	flag.Parse()

	if VERSION {
		fmt.Println(Version)
		os.Exit(0)
	}

	// Require folder argument to run
	if len(flag.Args()) == 0 {
		printUsage()
		os.Exit(1)
	}

	FILE_PATH = flag.Arg(0)

	// check path is a directory and can be accessed
	if err := checkDir(FILE_PATH); err != nil {
		log.Fatalf("%v", err)
	}

	if (CERT != "" && KEY == "") || (CERT == "" && KEY != "") {
		log.Fatal("Must provie both a key and certificate in PEM format!")
	}

	// if generating our own self-signed TLS cert/key
	if TLS {
		genKeys(HOST)
		cert = "cert.pem"
		key = "key.pem"
	}

	// use provided cert and key,
	// if these options are provided and self-signed option used, prefer
	// the explicitly given cert and key files
	if CERT != "" && KEY != "" {
		cert = CERT
		key = KEY
	}

	// User enabled basic auth, get password interactively
	if USER != "" {
		AUTH = true
		PASS = getPass()
	}

	// serve our static resources without having to individually host each file
	http.Handle("/files/", http.StripPrefix("/files/", basicAuth(http.FileServer(http.Dir(FILE_PATH)))))

	// setup our routes
	http.HandleFunc("/", redirectRoot)
	http.HandleFunc("/upload", uploadFile)
	http.HandleFunc("/view", viewDir)
	http.HandleFunc("/delete", deleteFile)

	// start server, bail if error
	serving := HOST + ":" + PORT
	if CERT != "" || TLS {
		// Set TLS preferences
		s := http.Server{
			Addr: serving,
			TLSConfig: &tls.Config{
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				},
			},
		}

		fmt.Println(`If using a self-signed certificate, ignore "unknown certificate" warnings`)
		fmt.Printf("\nServing on: https://%s\n", serving)
		err := s.ListenAndServeTLS(cert, key)
		log.Fatal(err)

	} else {
		fmt.Printf("\nServing on: http://%s\n", serving)
		err := http.ListenAndServe(serving, nil)
		log.Fatal(err)
	}

}

// printUsage - Print a simple usage message.
func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: mini [OPTION...] FOLDER\n")
	fmt.Fprintf(os.Stderr, `Try 'mini --help' or 'mini -h' for more information`+"\n")
}

// printHelp - Print a custom detailed help message.
func printHelp() {

	fmt.Fprintf(os.Stderr, "Usage: mini [OPTION...] FOLDER\n")
	fmt.Fprintf(os.Stderr, "Serve the given folder via an HTTP server\n\n")
	fmt.Fprintf(os.Stderr, "  -c, --cert                Use the provided PEM cert for TLS, MUST also use -k\n")
	fmt.Fprintf(os.Stderr, "  -i, --ip                  IP address to serve on; default 0.0.0.0\n")
	fmt.Fprintf(os.Stderr, "  -k, --key                 Use provided PEM key for TLS, MUST also use -c\n")
	fmt.Fprintf(os.Stderr, "  -p, --port                Port to serve on: default 8080\n")
	fmt.Fprintf(os.Stderr, "  -t, --tls                 Generate and use self-signed TLS cert.\n")
	fmt.Fprintf(os.Stderr, "  -u, --user                Enable basic auth. with this username\n")
	fmt.Fprintf(os.Stderr, "  -v, --verbose             Enable verbose logging mode\n")
	fmt.Fprintf(os.Stderr, "  -?, --help                Show this help message\n")
	fmt.Fprintf(os.Stderr, "  -V, --version             Print program version\n")
	fmt.Fprintf(os.Stderr, "\n")
}

// checkDir ensures we can access the given path and it is a directory.
func checkDir(path string) error {
	fd, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Error opening folder: %s", err)
	}

	info, err := fd.Stat()
	if err != nil {
		return fmt.Errorf("os.Stat() error: %s", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("Error: not a directory %s", path)
	}

	return nil
}

// exists - check if file exists
func exists(path string) error {
	fd, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Error opening file: %s", err)
	}

	info, err := fd.Stat()
	if err != nil {
		return fmt.Errorf("os.Stat() error: %s", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("Error: not a directory %s", path)
	}

	return nil
}

// sizeToStr converts a file size in bytes to a human friendy string.
func sizeToStr(n int64) string {
	if n == 0 {
		return "0B"
	}

	b := float64(n)
	units := []string{"B", "K", "M", "G", "T", "P", "E"}

	i := math.Floor(math.Log(b) / math.Log(1000))
	return strconv.FormatFloat((b/math.Pow(1000, i))*1, 'f', 1, 64) + units[int(i)]
}

/*
fileFunc is called on each file in the target directory and returns
a Files struct with the relevant information about each file.
*/
func fileFunc(path string) (Files, error) {
	var fs Files

	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		var f File
		f.Name = file.Name()
		f.Size = sizeToStr(file.Size())
		f.Mode = file.Mode().String()
		f.Date = file.ModTime().Format(time.UnixDate)
		f.IsDir = file.IsDir()
		fs = append(fs, f)
	}
	return fs, nil
}

// authFail sends a 401 unauthorized status code when a user fails to
// authenticate
func authFail(w http.ResponseWriter, r *http.Request) {
	if VERBOSE {
		log.Printf("CLIENT: %s PATH: %s INCORRECT USERNAME/PASS\n",
			r.RemoteAddr, r.RequestURI)
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="api"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

/*
basicAuth require authentication, if enabled on cmd line, to directly view
static files. This is basically a wrapper around Go's built in http.FileServer
which enables basic auth to view the files hosted by http.FileServer. Handy..
*/
func basicAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if VERBOSE {
			log.Printf("CLIENT: %s PATH: %s\n", r.RemoteAddr, r.RequestURI)
		}

		if AUTH {
			user, pass, ok := r.BasicAuth()
			if !ok || (user != USER || !checkPass(pass, PASS)) {
				authFail(w, r)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// redirectRoot redirects server root to /view?dir=/.
func redirectRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/view?dir=/", 302)
}

/*
viewDir is called when a person clicks a directory link, displays files in
the directory.
*/
func viewDir(w http.ResponseWriter, r *http.Request) {
	// the HTML template to display files
	htmltemp := `<!DOCTYPE html>
	<html lang="en" dir="ltr">
		<head>
			<meta charset="utf-8">
			<meta name="viewport"
				content="width=device-width, initial-scale=1, shrink-to-fit=no">
			<meta name="description" content="Simple file server">
			<!-- prevent favicon requests -->
			<link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgo=">
			<title>{{ .Title }}</title>
		</head>
		<body>
		<h2>{{.Title}}</h2>
		<p>
			<form enctype="multipart/form-data"
				action="/upload"
				method="POST">
				<fieldset>
					<legend>Upload a new file</legend>
					<input type="hidden" id="directory" type="text" name="directory" value="{{ .Directory }}">
					<input type="file" placeholder="Filename" name="file-upload" required>
					<button type="submit">Upload</button>
				</fieldset>
			</form>
		</p>
		{{ if eq .Directory "/" }}
			<p></p>
		{{ else }}
		<p>
			<a href="/view?dir={{ .Parent }}">To Parent Directory</a>
		</p>
		{{ end }}
		<p>
		<table>
			<thead>
				<tr>
					<th>Filename</th>
					<th>Size</th>
					<th>Mode</th>
					<th>Last Modified</th>
					<th>Delete</th>
				</tr>
			</thead>
			<tbody>
				{{range .Files}}
					<tr>
						<td>
							{{ if .IsDir }}
								{{ if eq $.Directory  "/" }}
									<a href="/view?dir={{ .Name }}">{{ .Name }}/</a>
								{{ else }}
									<a href="/view?dir={{ $.Directory }}/{{ .Name }}">{{ .Name }}/</a>
								{{ end }}
							{{ else }}
								{{ if eq $.Directory  "/" }}
									<a download href="../../files/{{ .Name }}">{{ .Name }}</a>
									
								{{ else }}
									<a download href="../../files/{{ $.Directory }}/{{ .Name }}">{{ .Name }}</a>
								{{ end }}
							{{ end }}
						</td>
						<td>{{ .Size }}</td>
						<td>{{ .Mode }}</td>
						<td>{{ .Date}}</td>
						<td>
							<form action="/delete" method="POST" class="form-example">
								<div>
									<input type="hidden" id="directory" type="text" name="directory" value="{{ $.Directory }}">
									<input type="hidden" id="file" type="file" name="filename" value="{{ .Name }}">
									<input type="submit" value="Delete">
								</div>
							</form>
					  </td>
					</tr>
				{{ end }}
			</tbody>
		</table>
		</p>
		</body>
	</html>`

	if VERBOSE {
		log.Printf("CLIENT: %s PATH: %s\n", r.RemoteAddr, r.RequestURI)
	}

	if AUTH {
		user, pass, ok := r.BasicAuth()
		if !ok || (user != USER || !checkPass(pass, PASS)) {
			authFail(w, r)
			return
		}
	}

	keys, ok := r.URL.Query()["dir"]

	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'key' is missing")
		http.Redirect(w, r, "/view?dir=/", 302)
		return
	}

	dir := filepath.Clean(keys[0])

	// Handle Windows paths, filepath is the OS independent way to handle paths
	dir = filepath.ToSlash(dir)

	// What is the parent for current folder?
	parent := filepath.Dir(dir)
	if parent == "." {
		parent = "/"
	}

	if strings.Contains(dir, "..") {
		// prevent path traversal
		http.Redirect(w, r, "/view?dir/", 302)
		return
	}

	// create real path from the server's root folder and navigated folder
	path := filepath.Clean(filepath.Join(FILE_PATH, dir))

	// get list of files in directory
	f, err := fileFunc(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create data for templates, parse and execute template
	title := "Directory listing for " + dir
	context := Context{title, dir, parent, f}
	templates := template.Must(template.New("foo").Parse(htmltemp))

	if err := templates.Execute(w, context); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// uploadFile called when a user chooses a file and clicks the upload button.
func uploadFile(w http.ResponseWriter, r *http.Request) {
	// Get the file from form
	file, fileHeader, err := r.FormFile("file-upload")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	/* Get directory value from the form so we know what directory to upload
	 * the file to */
	dir := filepath.Clean(r.FormValue("directory"))

	if strings.Contains(dir, "..") {
		// prevent path traversal, redirect to home page
		http.Redirect(w, r, "/view?dir=/", 302)
		return
	}

	path := filepath.Clean(filepath.Join(FILE_PATH, dir, fileHeader.Filename))

	// close uploaded file descriptor when done
	defer file.Close()

	// Create a new file in the correct directory
	dst, err := os.Create(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// close new file descriptor later
	defer dst.Close()

	// Copy the uploaded file to the filesystem
	// at the specified destination
	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if VERBOSE {
		log.Printf("CLIENT: %s UPLOAD: %s\n", r.RemoteAddr, fileHeader.Filename)
	}

	// reload the current page on successful upload
	http.Redirect(w, r, "view?dir="+dir, 302)
}

/*
deleteFile is called when the delete button is clicked next to a file.
It checks that the file exists in the FILE_PATH directory and deletes it
if it exists.
*/
func deleteFile(w http.ResponseWriter, r *http.Request) {
	// Get the name of the file to delete
	filename := r.FormValue("filename")
	if filename == "" {
		http.Error(w, "missing form value", http.StatusInternalServerError)
	}

	if strings.Contains(filename, "..") {
		// prevent path traversal deletion
		http.Redirect(w, r, "/", 302)
		return
	}

	// Get the directory to delete file from
	dir := r.FormValue("directory")

	// build path to the file
	path := filepath.Clean(filepath.Join(FILE_PATH, dir, filename))

	// Make sure file exists
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// ignore errors
	os.Remove(path)

	if VERBOSE {
		log.Printf("CLIENT: %s DELETED: %s\n", r.RemoteAddr, path)
	}

	// reload the current page
	http.Redirect(w, r, "view?dir="+dir, 302)
}

/*
genKeys - Generate self-signed TLS certificate and key.
Shamelessly stolen and modified from:
https://go.dev/src/crypto/tls/generate_cert.go
*/
func genKeys(host string) {

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	// Good for 2 weeks
	notAfter := notBefore.Add(14 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mini File Server"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Don't overwrite existing certs
	if err = exists("cert.pem"); err == nil {
		log.Fatal("Failed to write cert.pem: file already exists!")
	}

	// Write cert to cert.pem
	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}

	// Don't overwrite existing certs
	if err = exists("key.pem"); err == nil {
		log.Fatal("Failed to write key.pem: file already exists!")
	}

	// Write key to key.pem
	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}
}

/*
getPass - Get password interactively from stdin,
keep retrying until input matches.
NOTE: We could probably come up with a better way to hash passwords,
but IDK if it really matters.
*/
func getPass() string {
	reader := bufio.NewReader(os.Stdin)
	p1, p2 := "1", "2"

	// emulate a do-while to get and check that passwords entered match
	for bad := true; bad; bad = (p1 != p2) {
		//fmt.Printf("\nInput passwords did not match! Try again...\n")
		fmt.Print("\nEnter password: ")
		p1, _ = reader.ReadString('\n')
		fmt.Print("Enter password again: ")
		p2, _ = reader.ReadString('\n')
	}

	sha512 := sha512.New()
	sha512.Write([]byte(strings.TrimSpace(p1)))

	return base64.StdEncoding.EncodeToString(sha512.Sum(nil))
}

// checkPass checks the input password against the one setup on cmd line.
func checkPass(input, password string) bool {
	sha := sha512.New()
	sha.Write([]byte(input))
	inpass := base64.StdEncoding.EncodeToString(sha.Sum(nil))
	if inpass == password {
		return true
	}
	return false
}
