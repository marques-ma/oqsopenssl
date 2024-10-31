package oqsopenssl

import (
	"fmt"
	"os/exec"
	"io"
	"io/ioutil"
	"os"
)

// GeneratePrivateKey generates a private key using a specified algorithm.
func GeneratePrivateKey(algorithm, outputFile string) error {
	cmd := exec.Command("openssl", "genpkey", "-algorithm", algorithm, "-out", outputFile)
	return runCommand(cmd, "Failed to generate private key")
}

// GenerateRootCertificate creates a root CA certificate.
func GenerateRootCertificate(keyFile, outputFile, subj, spiffeID, configFile string, days int) error {
	cmd := exec.Command(
		"openssl", 
		"req", 
		"-nodes", 
		"-new", 
		"-x509", 
		"-key", keyFile, 
		"-out", outputFile, 
		"-days", fmt.Sprintf("%d", days), 
		"-subj", subj, 
		"-addext", fmt.Sprintf("subjectAltName=URI:%s", subj), 
		// fmt.Sprintf(`-extfile <(echo 'subjectAltName=URI:%s')`, spiffeID),
		"-config", configFile,
	)
	return runCommand(cmd, "Failed to generate root certificate")
}

// GenerateCSR generates a certificate signing request (CSR) for the server.
func GenerateCSR(algorithm, keyFile, csrFile, subj, spiffeID, configFile string) error {
	cmd := exec.Command(
		"openssl", 
		"req", 
		"-nodes", 
		"-new", 
		"-newkey", algorithm, 
		"-keyout", keyFile, 
		"-out", csrFile, 
		"-subj", subj, 
		"-config", configFile,
	)
	return runCommand(cmd, "Failed to generate CSR")
}

// SignCertificate signs the server certificate with the CA certificate.
func SignCertificate(csrFile, caCertFile, caKeyFile, spiffeID, outputFile string, days int) error {
	// Create a temporary file to hold the extensions
	extFile, err := ioutil.TempFile("", "extfile-*.conf")
	if err != nil {
		return fmt.Errorf("failed to create temporary extension file: %w", err)
	}
	defer os.Remove(extFile.Name()) // Clean up the temp file after use

	// Write the subjectAltName to the temporary file
	_, err = extFile.WriteString(fmt.Sprintf("subjectAltName=URI:%s\n", spiffeID))
	if err != nil {
		return fmt.Errorf("failed to write to temporary extension file: %w", err)
	}
	if err := extFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary extension file: %w", err)
	}

	// Prepare the command to sign the certificate
	cmd := exec.Command(
		"openssl",
		"x509",
		"-req",
		"-extfile", extFile.Name(), // Use the temporary extension file
		"-in", csrFile,
		"-CA", caCertFile,
		"-CAkey", caKeyFile,
		"-CAcreateserial",
		"-out", outputFile,
		"-days", fmt.Sprintf("%d", days),
	)

	// Execute the command and check for errors
	return runCommand(cmd, "Failed to sign certificate")
}

// StartServer starts the OpenSSL server with the specified certificate and key.
func StartServer(certFile string, keyFile string, caFile string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	cmd := exec.Command("openssl", "s_server", "-accept", "4433", "-state", "-cert", certFile, "-key", keyFile, "-tls1_3", "-Verify", "1", "-CAfile", caFile, "-www")

	// Create the StdoutPipe before starting the command
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Error creating stdout pipe:", err)
		return nil, nil, nil, err
	}

	// Create the StdinPipe before starting the command
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		fmt.Println("Error creating stdin pipe:", err)
		return nil, nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting OpenSSL s_server:", err)
		return nil, nil, nil, err
	}

	// Return both the command and the stdoutPipe if needed
	return cmd, stdinPipe, stdoutPipe, nil
}

// StartClient connects to the OpenSSL server using the specified client certificate and key.
func StartClient(address, certFile, keyFile, caCertFile string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, error) {
	cmd := exec.Command("openssl", "s_client", "-connect", address, "-state", "-cert", certFile, "-key", keyFile, "-tls1_3", "-CAfile", caCertFile)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Error creating stdout pipe:", err)
		return nil, nil, nil, err
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Println("Error creating stdin pipe:", err)
		return nil, nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting OpenSSL s_client:", err)
		return nil, nil, nil, err
	}
	return cmd, stdin, stdout, nil
}

// runCommand executes an exec.Command and captures its output.
func runCommand(cmd *exec.Cmd, errorMessage string) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s\n%s", errorMessage, err, string(output))
	}
	fmt.Println(string(output)) // Print command output for logging
	return nil
}

// ValidateCertificate checks if the provided certificate is valid against the specified CA certificate.
func ValidateCertificate(certFile, caCertFile string) error {
	cmd := exec.Command("openssl", "verify", "-CAfile", caCertFile, certFile)
	return runCommand(cmd, "Failed to validate certificate")
}
