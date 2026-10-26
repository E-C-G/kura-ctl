// Commande kura-ctl : console de gestion des sauvegardes Wasabi de l'éditeur.
// Application locale : sert son interface sur 127.0.0.1 et ouvre le navigateur.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/E-C-G/kura-ctl/internal/secrets"
	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/web"
)

// Renseignés à la compilation : -ldflags "-X main.version=… -X main.commit=…"
var (
	version = "dev"
	commit  = "none"
)

func main() {
	os.Exit(run())
}

func run() int {
	def, _ := os.UserConfigDir()
	dataDir := flag.String("data", filepath.Join(def, "kura-ctl"), "dossier de données (base, journal)")
	port := flag.String("port", "0", "port local (0 : port libre)")
	noBrowser := flag.Bool("no-browser", false, "ne pas ouvrir le navigateur")
	plainHost := flag.Bool("plain-host", false, "servir sur http://127.0.0.1:<port> plutôt que sous un nom aléatoire en .localhost (navigateur qui ne le résout pas)")
	reset := flag.Bool("reset", false, "effacer la clé d'administration du trousseau (mot de passe maître oublié)")
	showVersion := flag.Bool("version", false, "afficher la version")
	flag.Parse()
	if *showVersion {
		fmt.Printf("kura-ctl %s (commit %s)\n", version, commit)
		return 0
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	logFile, err := os.OpenFile(filepath.Join(*dataDir, "kura-ctl.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer logFile.Close()
	log := slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, logFile), nil))

	st, err := store.Open(filepath.Join(*dataDir, "kura-ctl.db"))
	if err != nil {
		log.Error("base", "err", err)
		return 1
	}
	defer st.Close()
	vault := secrets.System()

	if *reset {
		fmt.Print("Effacer la clé d'administration du trousseau ? Il faudra la ressaisir. Taper OUI : ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "OUI" {
			fmt.Println("abandon")
			return 1
		}
		if err := vault.Reset(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		_ = st.Audit(context.Background(), "réinitialisation du coffre", "console", store.ResultOK, "mot de passe maître oublié")
		fmt.Println("Clé effacée. Au prochain lancement, la console redemandera la configuration.")
		return 0
	}

	srv := &web.Server{Store: st, Vault: vault, Log: log, Version: version, PlainHost: *plainHost}
	ln, err := srv.Listen(*port)
	if err != nil {
		log.Error("écoute", "err", err)
		return 1
	}
	h, err := srv.Handler()
	if err != nil {
		log.Error("interface", "err", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go srv.Watch(ctx)
	hs := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()

	url := srv.URL()
	log.Info("console prête", "adresse", url, "données", *dataDir, "version", version)
	fmt.Printf("\nKura ctl : %s\n(Ctrl+C pour arrêter)\n", url)
	if !*plainHost {
		fmt.Println("Si le navigateur ne trouve pas cette adresse, relancer avec --plain-host.")
	}
	fmt.Println()
	if !*noBrowser {
		if err := openBrowser(url); err != nil {
			log.Warn("navigateur non ouvert : ouvrir l'adresse à la main", "err", err)
		}
	}
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serveur", "err", err)
		return 1
	}
	return 0
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() // pas de processus zombie
	return nil
}
