/*************************************************************************
 * Simple file server, defaults to seerving on port 8080. Allows file    *
 * upload, download, and deletion. Folders can be deleted if empty.      *
 *************************************************************************/
package main

import (
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Version = "mini server 0.0.2"

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

// global variables for command line arguments, only used in sprm()
var (
	hostG     string
	portG     string
	versionG  bool
	FILE_PATH string // folder to serve files from
)

// init is automatically called at start, setup cmd line args
func init() {

	// host/IP adddress
	flag.StringVar(&hostG, "ip", "0.0.0.0", "IP address to serve on, defaults to 0.0.0.0")
	flag.StringVar(&hostG, "i", "0.0.0.0", "IP shortcut")

	// version
	flag.BoolVar(&versionG, "version", false, "Print program version")
	flag.BoolVar(&versionG, "V", false, "Print program version")

	// port
	flag.StringVar(&portG, "port", "8080", "Port to listen on, defaults to 8080")
	flag.StringVar(&portG, "p", "8080", "Leave the original file unchanged")
}

func main() {
	// parse command line arguments
	flag.Usage = printHelp
	flag.Parse()

	if versionG {
		fmt.Println(Version)
		os.Exit(0)
	}

	// Require folder to serve argument in future
	if len(flag.Args()) == 0 {
		printUsage()
		os.Exit(1)
	}

	FILE_PATH = flag.Arg(0)

	// check path is a directory and can be accessed
	if err := checkDir(FILE_PATH); err != nil {
		log.Fatalf("%v", err)
	}

	// serve our static resources without having to individually host each file
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(FILE_PATH))))

	// setup our routes
	http.HandleFunc("/", handleRoute)
	http.HandleFunc("/upload", uploadFile)
	http.HandleFunc("/view", viewDir)
	http.HandleFunc("/delete", deleteFile)

	// start server
	serving := hostG + ":" + portG
	fmt.Printf("Serving on: %s\n", serving)
	http.ListenAndServe(serving, nil)
	//http.ListenAndServeTLS(hostG+":"+portG, "cert.pem", "key.pem", nil)
}

/** printUsage - Print a simple usage message
 *
 */
func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: server [OPTION...] FOLDER\n")
	fmt.Fprintf(os.Stderr, "Try `server --help' or `server -h' for more information\n")
}

/** printHelp - Print a custom help message
 *
 */
func printHelp() {

	fmt.Fprintf(os.Stderr, "Usage: server [OPTION...] FOLDER\n")
	fmt.Fprintf(os.Stderr, "Serve the given folder via an HTTP server\n\n")
	fmt.Fprintf(os.Stderr, "  -i, --ip                    IP address to server on; default 0.0.0.0\n")
	fmt.Fprintf(os.Stderr, "  -p, --port                  Port to serve on: default 8080\n")
	fmt.Fprintf(os.Stderr, "  -?, --help                  Show this help message\n")
	fmt.Fprintf(os.Stderr, "  -V, --version               Print program version\n")
	fmt.Fprintf(os.Stderr, "\n")
}

/*
checkDir ensures we can access the given path and that it points to a directory
*/
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

/*
sizeToStr converts a file size in bytes to a human friendy string
*/
func sizeToStr(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c",
		float64(b)/float64(div), "KMGTPE"[exp])
}

/*
fileFunc is called on each file in the target directory and returns
a File struct with the relevant information about each file
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

/*
handleRoute redirects server root to /view?dir=/
*/
func handleRoute(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/view?dir=/", 302)
}

/*
viewDir is called when a person clicks a directory link, displays files in
the directory
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
					<input type="file" placeholder="Filename" name="file-upload">
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

	keys, ok := r.URL.Query()["dir"]

	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'key' is missing")
		http.Redirect(w, r, "/view?dir=/", 302)
		return
	}

	dir := filepath.Clean(keys[0])
	// Handle Windows paths
	if dir == "\\" {
		dir = "/"
	}

	// Handle Windows paths
	dir = strings.ReplaceAll(dir, "\\", "/")

	parent := filepath.Dir(dir)
	if parent == "." {
		parent = "/"
	}

	if strings.Contains(dir, "..") {
		// prevent path traversal
		http.Redirect(w, r, "/view?dir/", 302)
		return
	}

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

/*
uploadFile called when a user chooses a file and clicks the upload button
*/
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

	defer file.Close()

	// Create a new file in the correct directory
	dst, err := os.Create(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer dst.Close()

	// Copy the uploaded file to the filesystem
	// at the specified destination
	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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

	// reload the current page
	http.Redirect(w, r, "view?dir="+dir, 302)
}
