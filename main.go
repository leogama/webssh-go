// webssh is a minimal web-based SSH client: it serves a single-page browser
// UI, and for each browser tab it opens an SSH connection to some other
// machine and bridges that connection's terminal (and file transfers) over
// a WebSocket. It is meant to run behind a reverse proxy that already
// terminates TLS and handles authentication (Caddy's basic_auth, in this
// fork) — this program itself speaks plain HTTP on localhost and, as of
// this branch, has no login of its own.
//
// The one piece of state this program keeps on disk is the list of SSH
// "connections" (host/user/credential) an admin has configured through the
// web UI — see connections.json and the encrypt/decrypt helpers below.
package main

import (
	// archive/zip: builds a .zip file in memory when a remote *directory*
	// is requested for download (see zipDirectory).
	"archive/zip"
	// bytes: bytes.Buffer is used as an in-memory io.Writer target for the
	// zip archive before it's base64-encoded and sent to the browser.
	"bytes"
	// crypto/aes + crypto/cipher: AES-GCM, used to encrypt the passwords/
	// private keys inside connections.json at rest (see encrypt/decrypt).
	"crypto/aes"
	"crypto/cipher"
	// crypto/rand: cryptographically secure randomness, used here only to
	// generate the GCM nonce for each encryption (see encrypt).
	"crypto/rand"
	// embed: lets the static/ directory (the HTML/CSS/JS frontend) be
	// compiled directly into the binary, so deployment is just one file.
	"embed"
	// encoding/base64: connections.json stores encrypted bytes as text, and
	// the SFTP file-transfer messages carry file contents as text too — both
	// go through base64 rather than raw bytes because JSON and the
	// WebSocket "data" message type are both text-based here.
	"encoding/base64"
	// encoding/hex: used once, to decode the WEBSSH_ENCRYPTION_KEY
	// environment variable from a hex string into raw key bytes.
	"encoding/hex"
	"encoding/json"
	// flag: command-line flags (just the two file-browser toggles, now that
	// -no-auth/-tls/-cert-file/-key-file have been removed on this branch).
	"flag"
	"fmt"
	// io: generic Reader/Writer helpers — io.ReadFull (fill a byte slice
	// completely or fail) and io.Copy (stream one file into another).
	"io"
	// io/fs: fs.Sub gives an fs.FS rooted at the "static" subdirectory of
	// the embedded filesystem, so URLs don't need a "/static" prefix baked
	// into every embedded path.
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	// sync: sync.RWMutex guards the in-memory `connections` map (many
	// concurrent readers — e.g. multiple open tabs listing connections —
	// but writes need exclusive access).
	"sync"
	"time"

	// github.com/google/uuid: generates a random ID for each new saved
	// connection (used as both the map key and the JSON "id" field).
	"github.com/google/uuid"
	// github.com/gorilla/websocket: the WebSocket implementation — upgrades
	// an HTTP request to a persistent bidirectional connection, used here
	// as the transport between the browser's terminal and the SSH session.
	"github.com/gorilla/websocket"
	// github.com/pkg/sftp: SFTP (SSH File Transfer Protocol) client, layered
	// on top of an already-open SSH connection — this is what actually lists,
	// reads and writes files on the remote machine for the file browser.
	"github.com/pkg/sftp"
	// golang.org/x/crypto/ssh: the SSH client itself — dialing,
	// authenticating, and opening interactive shell sessions.
	"golang.org/x/crypto/ssh"
)

// staticFiles embeds everything under static/ (index.html, script.js,
// style.css, plus the now-unused login.* pages left for a later HTML/JS
// cleanup pass) directly into the compiled binary. "all:" tells go:embed to
// include files that would otherwise be skipped for starting with "_" or
// "." — not needed here, but harmless, and it's what the upstream project
// shipped with.
//
//go:embed all:static
var staticFiles embed.FS

var (
	// encryptionKey is the 32-byte AES-256 key used by encrypt/decrypt
	// below. It's populated once at startup from the WEBSSH_ENCRYPTION_KEY
	// environment variable (see main) and never changes afterward — there's
	// no key rotation support.
	encryptionKey []byte
	// disableFileBrowser turns off listing/uploading/downloading entirely;
	// disableDownload turns off only the download half (listing and upload
	// still work). Both are set once from command-line flags in main and
	// read (never written) from every connected WebSocket's goroutines
	// afterward, so no mutex is needed for these two.
	disableDownload    bool
	disableFileBrowser bool
	// connections holds every configured SSH target, keyed by its UUID, with
	// Password/Key already decrypted for use — see loadConnections. This is
	// the process's only real "database", and it's just a Go map guarded by
	// connectionsMutex below, rebuilt from connections.json at startup and
	// rewritten to disk (via saveConnections) on every add/remove.
	connections      = make(map[string]SSHConnection)
	connectionsMutex sync.RWMutex
)

// connectionsFile is where the encrypted connection list is persisted
// between restarts — a relative path, so it lands wherever the process's
// working directory happens to be when it's started.
const connectionsFile = "connections.json"

// upgrader turns a normal HTTP request into a WebSocket connection (the
// browser's `new WebSocket(...)` call on the client side triggers this on
// the server). CheckOrigin below is a known-insecure placeholder inherited
// from upstream: returning true unconditionally means *any* website open in
// the same browser can open a WebSocket to this endpoint, and the browser
// will still attach cookies/cached credentials for this origin along with
// it — a cross-site request forgery angle on whatever sits in front of this
// app. Left as-is deliberately on this branch (it's flagged here, not
// fixed) — restricting it to the app's own Origin is a good next exercise.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Allow all origins for now, but you might want to restrict this in production
		return true
	},
}

// SSHConnection is one saved target: a host to dial, a user to authenticate
// as, and either a password or a private key (never both used at once — see
// handleWebSocket). The `omitempty` tags matter for handleConnections' GET
// response, which blanks Password/Key before encoding so secrets are never
// sent back to the browser.
type SSHConnection struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	Key      string `json:"key,omitempty"`
}

// --- Encryption/Decryption ---
//
// connections.json is written to disk with every SSHConnection's Password
// and Key fields passed through encrypt() first, and read back through
// decrypt() — see loadConnections/saveConnections. This is AES-256 in GCM
// mode (Galois/Counter Mode): a single stdlib-provided construction that
// gives both confidentiality (the data is unreadable without the key) and
// integrity (any tampering with the ciphertext is detected on decrypt,
// because gcm.Open fails rather than silently returning corrupted data).

// encrypt seals data under encryptionKey and returns it as base64 text
// (so it can sit inside a JSON string field). Each call generates a fresh
// random nonce — GCM's security depends on never reusing a nonce with the
// same key, so the nonce is generated here, not supplied by the caller.
func encrypt(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	// aes.NewCipher gives a block cipher (operates on fixed 16-byte blocks);
	// cipher.NewGCM wraps it into the authenticated stream mode actually used.
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// GCM's standard nonce size is 12 bytes; gcm.NonceSize() reports whatever
	// this particular construction expects, rather than hardcoding 12.
	nonce := make([]byte, gcm.NonceSize())
	// io.ReadFull keeps reading from rand.Reader until the nonce slice is
	// completely filled (a plain Read call is allowed to return fewer bytes
	// than asked for; ReadFull turns "short read" into an explicit error
	// instead of silently leaving part of the nonce as zero bytes).
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	// Seal appends the ciphertext to its first argument; passing `nonce`
	// there is a convenience so the nonce travels alongside the ciphertext
	// in one slice — decrypt() below relies on that layout to split them
	// back apart. The final nil is GCM's optional "additional data" field
	// (extra bytes that are authenticated but not encrypted) — unused here.
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt reverses encrypt: base64-decode, split the leading nonce back off,
// then open (decrypt + verify) the remainder. Returns an error if the data
// is malformed or — thanks to GCM's authentication — if it's been altered
// since it was encrypted.
func decrypt(encodedData string) ([]byte, error) {
	if encodedData == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	// Slice back apart the [nonce][ciphertext] layout encrypt() produced.
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// wsMessage is the single envelope shape used for every message exchanged
// over the WebSocket in both directions — Type says which of the fields
// below are meaningful for that particular message (see the switch in
// handleWebSocket and the various writeWs*/handleFile* functions). Using one
// struct for every message type is simple at the cost of most fields being
// irrelevant most of the time (hence `omitempty` throughout, so an unused
// field doesn't clutter the JSON on the wire).
type wsMessage struct {
	Type     string `json:"type"`               // "data" | "resize" | "upload" | "list" | "download" | "stdout" | "status" | "error"
	Payload  string `json:"payload,omitempty"`  // terminal bytes, or a file's base64 content, depending on Type
	Filename string `json:"filename,omitempty"` // for upload/download
	Cols     int    `json:"cols,omitempty"`     // for "resize"
	Rows     int    `json:"rows,omitempty"`     // for "resize"
	Path     string `json:"path,omitempty"`     // remote path, for list/upload/download
}

// --- HTTP Handlers ---

// handleRoot serves the single-page app's HTML shell for every page load.
// There's no auth check here on this branch — whatever sits in front of
// this process (Caddy's basic_auth) is expected to have already decided
// whether this request is allowed through at all.
func handleRoot(w http.ResponseWriter, r *http.Request) {
	content, _ := staticFiles.ReadFile("static/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

// writeWsJSON marshals a wsMessage and sends it as a single WebSocket text
// frame — this is the one function every server-to-browser message goes
// through (terminal output, status lines, file listings and downloads).
func writeWsJSON(ws *websocket.Conn, msgType, payload string) error {
	msg := wsMessage{Type: msgType, Payload: payload}
	marshaledMsg, _ := json.Marshal(msg)
	return ws.WriteMessage(websocket.TextMessage, marshaledMsg)
}

// writeWsError is writeWsJSON specialized for the "error" message type —
// used by the SFTP-backed file operations below to report a failure to the
// browser without tearing down the whole WebSocket connection.
func writeWsError(ws *websocket.Conn, err error) {
	msg := wsMessage{Type: "error", Payload: err.Error()}
	marshaledMsg, _ := json.Marshal(msg)
	// It's fine to ignore the error here, as the connection might be closing.
	_ = ws.WriteMessage(websocket.TextMessage, marshaledMsg)
}

// loadConnections reads connections.json (if it exists) into the in-memory
// `connections` map, decrypting each entry's Password/Key along the way. A
// missing file just means "no connections configured yet" (not an error); a
// corrupt file, or an entry whose ciphertext no longer decrypts (e.g. it was
// encrypted under a different WEBSSH_ENCRYPTION_KEY), is logged and that
// entry is dropped rather than aborting startup entirely.
func loadConnections() {
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()
	file, err := os.ReadFile(connectionsFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Warning: Could not read connections file: %v", err)
		}
		connections = make(map[string]SSHConnection)
		return
	}

	// On disk, Password/Key are still base64-encoded ciphertext at this
	// point — decoding into SSHConnection just parses the JSON shape.
	var encryptedConnections map[string]SSHConnection
	if err := json.Unmarshal(file, &encryptedConnections); err != nil {
		log.Printf("Warning: Could not parse connections file: %v. Starting with empty connections.", err)
		connections = make(map[string]SSHConnection)
		return
	}

	connections = make(map[string]SSHConnection)
	for id, conn := range encryptedConnections {
		decryptedPassword, err := decrypt(conn.Password)
		if err != nil {
			log.Printf("Warning: Failed to decrypt password for connection '%s' (%s): %v", conn.Name, id, err)
			continue // Skip this connection
		}
		decryptedKey, err := decrypt(conn.Key)
		if err != nil {
			log.Printf("Warning: Failed to decrypt key for connection '%s' (%s): %v", conn.Name, id, err)
			continue // Skip this connection
		}
		conn.Password = string(decryptedPassword)
		conn.Key = string(decryptedKey)
		connections[id] = conn
	}
	log.Printf("Loaded %d connections.", len(connections))
}

// saveConnections is loadConnections in reverse: take the in-memory (plain-
// text) `connections` map, re-encrypt each Password/Key, and write the
// whole map back out as indented JSON. It's called after every add/delete
// in handleConnections, so connections.json is always a full snapshot
// rather than an append-only log.
func saveConnections() {
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	encryptedConnections := make(map[string]SSHConnection)
	for id, conn := range connections {
		// Errors from encrypt() are ignored here (`_`) — in practice the only
		// way it fails is a bad encryptionKey, which would already have made
		// every other encrypt/decrypt call fail too and been logged elsewhere.
		encryptedPassword, _ := encrypt([]byte(conn.Password))
		encryptedKey, _ := encrypt([]byte(conn.Key))
		encryptedConn := conn
		encryptedConn.Password = encryptedPassword
		encryptedConn.Key = encryptedKey
		encryptedConnections[id] = encryptedConn
	}

	data, err := json.MarshalIndent(encryptedConnections, "", "  ")
	if err != nil {
		log.Printf("Error marshaling connections: %v", err)
		return
	}
	// 0600: readable/writable only by whatever user runs this process — the
	// file holds encrypted secrets, but there's no reason to make it
	// world-readable on top of that.
	os.WriteFile(connectionsFile, data, 0600)
}

// handleConnections is the CRUD endpoint the frontend uses to manage the
// saved connection list: GET to populate the picker, POST to add a new one,
// DELETE to remove one. All three cases share the connectionsMutex-guarded
// `connections` map; there's no PUT/edit — the frontend deletes and re-adds
// instead.
func handleConnections(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		connectionsMutex.RLock()
		defer connectionsMutex.RUnlock()
		var connList []SSHConnection
		for _, conn := range connections {
			conn.Password = "" // Never send sensitive data to the client
			conn.Key = ""      // Never send sensitive data to the client
			connList = append(connList, conn)
		}
		json.NewEncoder(w).Encode(connList)
	case "POST":
		var conn SSHConnection
		// Decode errors are ignored here — a malformed body just results in
		// a zero-value SSHConnection being saved, which is harmless (it'll
		// simply fail to connect later) rather than a crash.
		json.NewDecoder(r.Body).Decode(&conn)
		// The client never gets to pick its own ID — always server-generated,
		// so there's no way to overwrite an existing entry through POST.
		conn.ID = uuid.New().String()
		connectionsMutex.Lock()
		connections[conn.ID] = conn
		connectionsMutex.Unlock()
		saveConnections()
		w.WriteHeader(http.StatusCreated)
	case "DELETE":
		id := r.URL.Query().Get("id")
		connectionsMutex.Lock()
		delete(connections, id) // deleting a non-existent id is a silent no-op in Go
		connectionsMutex.Unlock()
		saveConnections()
		w.WriteHeader(http.StatusOK)
	}
}

// handleWebSocket is the heart of the app: for one browser tab, it dials the
// chosen SSH connection, starts an interactive shell, and then bridges
// bytes in both directions between that shell and the browser's WebSocket
// for as long as the tab stays open. It also dispatches the file-browser
// operations (list/upload/download), which reuse the same SSH connection
// via SFTP rather than opening a second one.
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// ?id=<uuid> picks which saved connection to use — set by the frontend
	// when the user clicks a saved connection before this WebSocket opens.
	connID := r.URL.Query().Get("id")
	connectionsMutex.RLock()
	sshConn, ok := connections[connID]
	connectionsMutex.RUnlock()
	if !ok {
		http.Error(w, "Connection not found", http.StatusNotFound)
		return
	}

	// Upgrade swaps the HTTP response out for a raw, bidirectional WebSocket
	// connection — from here on, ws.ReadMessage/WriteMessage replace the
	// usual request/response cycle for the rest of this function.
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade error: %v", err)
		return
	}
	defer ws.Close()

	// Pick the auth method based on what's saved for this connection: a
	// private key if one is set, otherwise a password. The two are mutually
	// exclusive here — there's no attempt to try one and fall back to the
	// other.
	var auth ssh.AuthMethod
	if sshConn.Key != "" {
		// ParsePrivateKey expects PEM-encoded key bytes (the raw contents of
		// an id_ed25519/id_rsa-style file); it does not currently support an
		// encrypted/passphrase-protected key (that would need
		// ssh.ParsePrivateKeyWithPassphrase instead).
		signer, err := ssh.ParsePrivateKey([]byte(sshConn.Key))
		if err != nil {
			writeWsJSON(ws, "status", "Error parsing private key")
			return
		}
		auth = ssh.PublicKeys(signer)
	} else {
		auth = ssh.Password(sshConn.Password)
	}

	config := &ssh.ClientConfig{
		User: sshConn.User,
		Auth: []ssh.AuthMethod{auth},
		// InsecureIgnoreHostKey means the SSH client accepts whatever host
		// key the target machine presents, with no verification at all —
		// there's no protection here against a machine-in-the-middle between
		// this server and the target. This is a known, deliberately
		// unaddressed gap on this branch (see PLANS.md) — a real fix would
		// pin each connection's expected host key (learned on first connect,
		// like OpenSSH's TOFU, or configured up front) instead of a callback
		// that always returns nil.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// If no port was given, assume the standard SSH port.
	host := sshConn.Host
	if !strings.Contains(host, ":") {
		host = fmt.Sprintf("%s:22", host)
	}

	// ssh.Dial does both the TCP connect and the full SSH handshake
	// (key exchange + the auth method configured above) in one call.
	sshClient, err := ssh.Dial("tcp", host, config)
	if err != nil {
		writeWsJSON(ws, "status", fmt.Sprintf("SSH connection failed: %v", err))
		return
	}
	defer sshClient.Close()

	// A "session" is one logical command/shell channel multiplexed over the
	// single underlying SSH connection — SSH allows several sessions per
	// connection, though this code only ever opens one.
	session, err := sshClient.NewSession()
	if err != nil {
		writeWsJSON(ws, "status", "Failed to create SSH session")
		return
	}
	defer session.Close()

	// RequestPty asks the remote side for a pseudo-terminal (so the remote
	// shell behaves interactively — prompts, line editing, colors — rather
	// than running as a plain non-interactive pipe). "xterm" is the terminal
	// type advertised (matches what most terminal emulators, including the
	// one presumably running in the browser via xterm.js, identify as); 80x40
	// is the initial size, corrected soon after by the frontend's own
	// "resize" message once it knows the real browser window size. ECHO: 1
	// asks the remote pty to echo typed characters back itself.
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	session.RequestPty("xterm", 80, 40, modes)

	// StdoutPipe/StdinPipe return the ends of the pipes connected to the
	// remote shell's stdout/stdin — writes to stdin are sent to the remote
	// shell as keystrokes; reads from stdout are the shell's output.
	stdout, _ := session.StdoutPipe()
	stdin, _ := session.StdinPipe()
	// Shell() actually starts the interactive shell on the remote side (as
	// opposed to session.Run("some command"), which would run one command
	// and exit) — after this, stdin/stdout are "live".
	session.Shell()

	// Two independent flows need to run concurrently for the rest of this
	// function's life: remote-shell-output -> browser (this goroutine) and
	// browser-input -> remote-shell (the for loop below, in the original
	// goroutine). Neither can be a simple sequential "read one side, write
	// the other" loop because either side can produce data at any time.
	go func() {
		defer ws.Close() // closing ws also unblocks the ws.ReadMessage() loop below once its Read fails
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				// EOF (remote shell exited) or the SSH connection died —
				// either way, there's nothing more to forward.
				return
			}
			writeWsJSON(ws, "stdout", string(buf[:n]))
		}
	}()

	// Main loop: block on the next message the browser sends, and act on
	// its Type. This runs until ws.ReadMessage errors (browser closed the
	// tab/connection, or the goroutine above closed ws first).
	for {
		_, p, err := ws.ReadMessage()
		if err != nil {
			return
		}
		var msg wsMessage
		json.Unmarshal(p, &msg) // errors ignored — a malformed message just falls through the switch below doing nothing
		switch msg.Type {
		case "data":
			// Keystrokes/pasted text from the browser's terminal — forward
			// verbatim to the remote shell's stdin.
			stdin.Write([]byte(msg.Payload))
		case "resize":
			// Browser terminal was resized (window resize, panel drag, etc.)
			// — tell the remote pty so line-wrapping and full-screen programs
			// (editors, pagers) redraw correctly.
			session.WindowChange(msg.Rows, msg.Cols)
		case "upload":
			if !disableFileBrowser {
				// Each file operation opens its own SFTP session (see
				// handleFileUpload etc.) and runs in its own goroutine so a
				// slow transfer doesn't block the terminal's data/resize
				// handling above.
				go handleFileUpload(sshClient, ws, msg.Path, msg.Filename, msg.Payload)
			}
		case "list":
			if !disableFileBrowser {
				go handleFileListing(sshClient, ws, msg.Path)
			}
		case "download":
			if !disableFileBrowser && !disableDownload {
				go handleFileDownload(sshClient, ws, msg.Path)
			}
		}
	}
}

// handleFileListing answers a "list" request: directory contents of `path`
// (or the SFTP session's default working directory, if path is empty) on
// the remote machine, sent back as a "list" message whose Payload is a
// small JSON object (not itself wrapped in another layer of struct — built
// with a plain map + json.Marshal instead of wsMessage's Payload string,
// since the shape here doesn't fit "Type"+"Payload" as text).
func handleFileListing(sshClient *ssh.Client, ws *websocket.Conn, path string) {
	if disableFileBrowser {
		writeWsError(ws, fmt.Errorf("file browser is disabled by the server administrator"))
		return
	}
	// sftp.NewClient starts an SFTP subsystem session over the existing SSH
	// connection — this is a second logical channel alongside the shell
	// session opened in handleWebSocket, not a new network connection.
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		writeWsError(ws, fmt.Errorf("could not start SFTP session: %w", err))
		return
	}
	defer sftpClient.Close()

	requestedPath := path
	if requestedPath == "" {
		requestedPath, err = sftpClient.Getwd()
		if err != nil {
			writeWsError(ws, fmt.Errorf("could not get working directory: %w", err))
			return
		}
	}

	// ReadDir returns fs.FileInfo-like entries for one directory (not
	// recursive) — analogous to os.ReadDir, but talking SFTP to the remote
	// machine instead of the local filesystem.
	files, err := sftpClient.ReadDir(requestedPath)
	if err != nil {
		writeWsError(ws, fmt.Errorf("could not read directory '%s': %w", requestedPath, err))
		return
	}

	// A local, unexported type — only used to shape this one JSON response,
	// so it's declared right where it's used rather than at package level.
	type fileInfo struct {
		Name  string    `json:"name"`
		Size  int64     `json:"size"`
		IsDir bool      `json:"isDir"`
		Mod   time.Time `json:"mod"`
	}

	var fileList []fileInfo
	for _, f := range files {
		fileList = append(fileList, fileInfo{
			Name:  f.Name(),
			Size:  f.Size(),
			IsDir: f.IsDir(),
			Mod:   f.ModTime(),
		})
	}

	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"path":  requestedPath, // CRITICAL FIX: Return the path that was requested by the client.
		"files": fileList,
	})

	writeWsJSON(ws, "list", string(payloadBytes))
}

// handleFileDownload answers a "download" request for `path`. A regular
// file is read whole into memory and sent back base64-encoded in one
// message; a directory is instead handed off to zipDirectory, which walks
// it and returns a single .zip. Either way, the whole result has to fit in
// memory before it's sent — there's no streaming/chunking, which matters on
// a memory-constrained host if a large file or directory is ever requested.
func handleFileDownload(sshClient *ssh.Client, ws *websocket.Conn, path string) {
	if disableFileBrowser || disableDownload {
		writeWsError(ws, fmt.Errorf("file download is disabled by the server administrator"))
		return
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		writeWsError(ws, fmt.Errorf("could not start SFTP session: %w", err))
		return
	}
	defer sftpClient.Close()

	srcFile, err := sftpClient.Open(path)
	if err != nil {
		writeWsError(ws, fmt.Errorf("could not open remote file '%s': %w", path, err))
		return
	}
	defer srcFile.Close()

	// Check if it's a directory
	stat, err := srcFile.Stat()
	if err != nil {
		writeWsError(ws, fmt.Errorf("could not stat remote file '%s': %w", path, err))
		return
	}
	if stat.IsDir() {
		go zipDirectory(sshClient, ws, path)
	} else {
		// io.ReadAll drains the whole remote file into one []byte — simple,
		// but means a multi-hundred-MB file would be held entirely in this
		// process's memory before base64-encoding it and sending it on.
		content, err := io.ReadAll(srcFile)
		if err != nil {
			writeWsError(ws, fmt.Errorf("could not read remote file '%s': %w", path, err))
			return
		}
		base64Content := base64.StdEncoding.EncodeToString(content)
		// filepath.Base extracts just the final path component ("notes.txt"
		// out of "/home/user/notes.txt") for the filename the browser will
		// save the download as.
		filename := filepath.Base(path)
		writeWsJSON(ws, "download", fmt.Sprintf(`{"filename": "%s", "payload": "%s"}`, filename, base64Content))
	}
}

// handleFileUpload answers an "upload" message: decode the base64 payload
// the browser sent and write it to `path`/`filename` on the remote machine
// via SFTP. Status updates go back over the WebSocket as plain "status"
// text messages (formatted with \r\n so they render like terminal output
// if the frontend just dumps them into the same terminal view).
func handleFileUpload(sshClient *ssh.Client, ws *websocket.Conn, path, filename, base64Content string) {
	if disableFileBrowser {
		writeWsError(ws, fmt.Errorf("file browser is disabled by the server administrator"))
		return
	}

	// A small local closure so every status line below is formatted the
	// same way, without repeating the writeWsJSON(ws, "status", ...) call.
	sendStatus := func(message string) {
		writeWsJSON(ws, "status", fmt.Sprintf("\r\n%s\r\n", message))
	}
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sendStatus(fmt.Sprintf("Error: Could not start SFTP session: %v", err))
		return
	}
	defer sftpClient.Close()
	fileContent, _ := base64.StdEncoding.DecodeString(base64Content) // a decode error here just yields an empty file — not specially reported

	remotePath := filename
	if path != "" {
		// sftpClient.Join is SFTP's equivalent of filepath.Join — joins path
		// segments with the remote server's separator convention (always
		// "/", since SFTP paths are POSIX-style regardless of what OS this
		// program itself runs on).
		remotePath = sftpClient.Join(path, filename)
	}

	dstFile, err := sftpClient.Create(remotePath)
	if err != nil {
		sendStatus(fmt.Sprintf("Error: Could not create remote file %s: %v", filename, err))
		return
	}
	defer dstFile.Close()
	dstFile.Write(fileContent)
	sendStatus(fmt.Sprintf("File '%s' uploaded successfully.", filename))
}

// zipDirectory streams a remote directory tree into a .zip archive built
// entirely in memory (via the bytes.Buffer), then sends the whole archive
// back the same way handleFileDownload sends a single file. Called from
// handleFileDownload when the requested path turns out to be a directory.
func zipDirectory(sshClient *ssh.Client, ws *websocket.Conn, remotePath string) {
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		writeWsError(ws, fmt.Errorf("could not start SFTP session for zipping: %w", err))
		return
	}
	defer sftpClient.Close()

	buf := new(bytes.Buffer)
	// zip.NewWriter wraps any io.Writer (here, the in-memory buffer — it
	// could equally be a file or a network connection) and exposes
	// Create(name) to start writing a new entry into the archive.
	zipWriter := zip.NewWriter(buf)

	// sftpClient.Walk is SFTP's analogue of filepath.Walk/fs.WalkDir: it
	// visits remotePath and everything under it, one entry per Step() call,
	// depth-first.
	walker := sftpClient.Walk(remotePath)
	for walker.Step() {
		if walker.Err() != nil {
			writeWsError(ws, fmt.Errorf("failed during directory walk: %w", walker.Err()))
			return
		}

		// Get the relative path for the zip file structure
		relPath, err := filepath.Rel(remotePath, walker.Path())
		if err != nil {
			writeWsError(ws, fmt.Errorf("could not get relative path for '%s': %w", walker.Path(), err))
			return
		}
		// For the root directory itself
		if relPath == "." {
			continue
		}

		info := walker.Stat()
		if info.IsDir() {
			// Create a directory entry in the zip file
			// A trailing "/" is the zip format's convention for an explicit
			// (otherwise-empty) directory entry.
			_, err := zipWriter.Create(relPath + "/")
			if err != nil {
				writeWsError(ws, fmt.Errorf("could not create directory in zip: %w", err))
				return
			}
		} else {
			// Create a file entry in the zip file
			fileWriter, err := zipWriter.Create(relPath)
			if err != nil {
				writeWsError(ws, fmt.Errorf("could not create file in zip: %w", err))
				return
			}
			// Open the remote file and copy its content
			// io.Copy streams from the remote file straight into the zip
			// entry without a whole extra manual buffer/loop.
			srcFile, err := sftpClient.Open(walker.Path())
			if err == nil {
				io.Copy(fileWriter, srcFile)
				srcFile.Close()
			}
		}
	}

	// Flush the zip's central directory record — a zip archive isn't
	// actually complete/valid until Close() writes this trailer.
	zipWriter.Close()

	base64Content := base64.StdEncoding.EncodeToString(buf.Bytes())
	zipFilename := filepath.Base(remotePath) + ".zip"
	writeWsJSON(ws, "download", fmt.Sprintf(`{"filename": "%s", "payload": "%s"}`, zipFilename, base64Content))
}

// handleFeatures tells the frontend which optional features are actually
// enabled server-side (set via the -disable-download/-disable-file-browser
// flags), so the UI can hide buttons for things that would just fail if
// clicked, rather than the frontend having to guess or hardcode this.
func handleFeatures(w http.ResponseWriter, r *http.Request) {
	features := map[string]bool{
		"download":    !disableDownload && !disableFileBrowser,
		"fileBrowser": !disableFileBrowser,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(features)
}

func main() {
	// flag.BoolVar registers a flag and binds it directly to the given
	// variable's address — flag.Parse() below then fills in disableDownload/
	// disableFileBrowser from whatever was passed on the command line (or
	// leaves them at their zero value, false, if the flag wasn't given).
	flag.BoolVar(&disableDownload, "disable-download", false, "Disable only the file download functionality")
	flag.BoolVar(&disableFileBrowser, "disable-file-browser", false, "Disable the entire file browser (upload, download, list)")
	flag.Parse()

	// The at-rest encryption key for connections.json — required, and never
	// generated automatically, since losing/rotating it silently would just
	// make every saved connection's password/key permanently undecryptable.
	keyHex := os.Getenv("WEBSSH_ENCRYPTION_KEY")
	if keyHex == "" {
		log.Fatal("FATAL: Environment variable WEBSSH_ENCRYPTION_KEY must be set to a 64-character hex string (32 bytes).")
	}
	var err error
	encryptionKey, err = hex.DecodeString(keyHex)
	if err != nil || len(encryptionKey) != 32 {
		log.Fatal("FATAL: WEBSSH_ENCRYPTION_KEY must be a valid 64-character hex string (32 bytes).")
	}

	loadConnections()

	// fs.Sub gives a view of staticFiles rooted at "static/", so
	// http.FileServer below serves e.g. "index.html" instead of
	// "static/index.html" for a request to "/static/index.html" (the
	// http.StripPrefix wrapper on the route below removes the "/static/"
	// part of the URL path before it reaches this file server).
	staticFS, _ := fs.Sub(staticFiles, "static")
	staticServer := http.FileServer(http.FS(staticFS))

	// http.Handle/HandleFunc register routes on the default (global)
	// ServeMux, which http.ListenAndServe(..., nil) below then uses
	// implicitly. No auth wrapper around any of these on this branch —
	// see the package doc comment at the top of this file.
	http.Handle("/static/", http.StripPrefix("/static/", staticServer))
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/api/connections", handleConnections)
	http.HandleFunc("/ws", handleWebSocket)
	http.HandleFunc("/api/features", handleFeatures)

	// Plain HTTP only — TLS is Caddy's job when this runs behind it. Bind
	// address is implicit here (":8080" without a host means "all
	// interfaces"); in the deployed setup this is expected to be reached
	// only via a reverse proxy on localhost, not directly from outside.
	log.Println("Server started on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
