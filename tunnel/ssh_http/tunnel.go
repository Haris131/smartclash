package ssh_http

import (
    "bufio"
    "context"
    "crypto/tls"
    "encoding/json"
    "errors"
    "fmt"
    "math/rand"
    "net"
    "net/http"
    "sort"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/metacubex/mihomo/log"
)

// ==============================
// DNS Caching System
// ==============================

// DNSCacheEntry represents a cached DNS entry
type DNSCacheEntry struct {
    IPs        []net.IP
    Expiration time.Time
    LastUsed   time.Time
    Hits       int
    Failures   int
    LastError  string
}

// DNSCache is a thread-safe DNS cache
type DNSCache struct {
    mu      sync.RWMutex
    cache   map[string]*DNSCacheEntry
    ttl     time.Duration
    maxSize int
    hits    int64
    misses  int64
    evictions int64
}

// NewDNSCache creates a new DNS cache
func NewDNSCache(ttl time.Duration, maxSize int) *DNSCache {
    if ttl <= 0 {
        ttl = 5 * time.Minute
    }
    if maxSize <= 0 {
        maxSize = 1000
    }
    
    return &DNSCache{
        cache:   make(map[string]*DNSCacheEntry),
        ttl:     ttl,
        maxSize: maxSize,
    }
}

// Get retrieves DNS entries from cache
func (d *DNSCache) Get(host string) ([]net.IP, bool) {
    d.mu.RLock()
    entry, exists := d.cache[host]
    d.mu.RUnlock()
    
    if !exists {
        atomic.AddInt64(&d.misses, 1)
        return nil, false
    }
    
    now := time.Now()
    if now.After(entry.Expiration) {
        d.mu.Lock()
        delete(d.cache, host)
        d.mu.Unlock()
        atomic.AddInt64(&d.misses, 1)
        return nil, false
    }
    
    entry.LastUsed = now
    entry.Hits++
    atomic.AddInt64(&d.hits, 1)
    
    // Return a copy to prevent modification
    ips := make([]net.IP, len(entry.IPs))
    copy(ips, entry.IPs)
    
    return ips, true
}

// Set stores DNS entries in cache
func (d *DNSCache) Set(host string, ips []net.IP) {
    d.mu.Lock()
    defer d.mu.Unlock()
    
    // Cleanup if cache is too large
    if len(d.cache) >= d.maxSize {
        d.cleanupLocked()
    }
    
    d.cache[host] = &DNSCacheEntry{
        IPs:        ips,
        Expiration: time.Now().Add(d.ttl),
        LastUsed:   time.Now(),
        Hits:       0,
        Failures:   0,
    }
}

// SetWithError stores a failed DNS lookup
func (d *DNSCache) SetWithError(host string, err error) {
    d.mu.Lock()
    defer d.mu.Unlock()
    
    entry, exists := d.cache[host]
    if exists {
        entry.Failures++
        entry.LastError = err.Error()
        // Shorten TTL for failed entries
        entry.Expiration = time.Now().Add(d.ttl / 2)
    }
}

// Remove removes an entry from cache
func (d *DNSCache) Remove(host string) {
    d.mu.Lock()
    defer d.mu.Unlock()
    delete(d.cache, host)
}

// cleanupLocked removes expired entries (must be called with lock held)
func (d *DNSCache) cleanupLocked() {
    now := time.Now()
    var toDelete []string
    
    // First pass: collect expired entries
    for host, entry := range d.cache {
        if now.After(entry.Expiration) {
            toDelete = append(toDelete, host)
        }
    }
    
    // Second pass: if still too large, remove least recently used
    if len(d.cache)-len(toDelete) > d.maxSize {
        entries := make([]struct {
            host     string
            lastUsed time.Time
            hits     int
        }, 0, len(d.cache))
        
        for host, entry := range d.cache {
            found := false
            for _, del := range toDelete {
                if del == host {
                    found = true
                    break
                }
            }
            if !found {
                entries = append(entries, struct {
                    host     string
                    lastUsed time.Time
                    hits     int
                }{
                    host:     host,
                    lastUsed: entry.LastUsed,
                    hits:     entry.Hits,
                })
            }
        }
        
        // Sort by last used (oldest first) and hits (fewest first)
        sort.Slice(entries, func(i, j int) bool {
            if entries[i].lastUsed.Equal(entries[j].lastUsed) {
                return entries[i].hits < entries[j].hits
            }
            return entries[i].lastUsed.Before(entries[j].lastUsed)
        })
        
        // Remove enough entries to get below maxSize
        toRemove := len(entries) - (d.maxSize - len(toDelete))
        for i := 0; i < toRemove && i < len(entries); i++ {
            toDelete = append(toDelete, entries[i].host)
        }
    }
    
    // Delete collected entries
    for _, host := range toDelete {
        delete(d.cache, host)
        atomic.AddInt64(&d.evictions, 1)
    }
}

// Stats returns cache statistics
func (d *DNSCache) Stats() map[string]interface{} {
    d.mu.RLock()
    defer d.mu.RUnlock()
    
    return map[string]interface{}{
        "size":       len(d.cache),
        "hits":       atomic.LoadInt64(&d.hits),
        "misses":     atomic.LoadInt64(&d.misses),
        "evictions":  atomic.LoadInt64(&d.evictions),
        "max_size":   d.maxSize,
        "ttl":        d.ttl.String(),
    }
}

// Clear clears the cache
func (d *DNSCache) Clear() {
    d.mu.Lock()
    defer d.mu.Unlock()
    d.cache = make(map[string]*DNSCacheEntry)
}

// Global DNS cache with default settings
var globalDNSCache = NewDNSCache(5*time.Minute, 1000)

// ==============================
// Error Types and Helpers
// ==============================

// DialError represents a detailed dial error
type DialError struct {
    Stage      string
    Host       string
    Address    string
    Underlying error
    IsTimeout  bool
    IsDNSError bool
    IsNetwork  bool
    Attempt    int
    TotalTime  time.Duration
    Timestamp  time.Time
}

func (e *DialError) Error() string {
    errorType := "unknown"
    if e.IsTimeout {
        errorType = "timeout"
    } else if e.IsDNSError {
        errorType = "dns"
    } else if e.IsNetwork {
        errorType = "network"
    }
    
    return fmt.Sprintf("dial error [%s] at %s for %s (%s): %v (attempt %d, time %v)",
        errorType, e.Stage, e.Host, e.Address, e.Underlying, e.Attempt, e.TotalTime)
}

func (e *DialError) Unwrap() error {
    return e.Underlying
}

// JSON returns JSON representation of the error
func (e *DialError) JSON() string {
    data := map[string]interface{}{
        "stage":       e.Stage,
        "host":        e.Host,
        "address":     e.Address,
        "error":       e.Underlying.Error(),
        "is_timeout":  e.IsTimeout,
        "is_dns":      e.IsDNSError,
        "is_network":  e.IsNetwork,
        "attempt":     e.Attempt,
        "total_time":  e.TotalTime.String(),
        "timestamp":   e.Timestamp.Format(time.RFC3339),
    }
    
    jsonData, _ := json.Marshal(data)
    return string(jsonData)
}

// ConnectionStats tracks connection statistics
type ConnectionStats struct {
    DialAttempts    int                    `json:"dial_attempts"`
    SuccessfulDials int                    `json:"successful_dials"`
    FailedDials     int                    `json:"failed_dials"`
    TotalDialTime   time.Duration          `json:"total_dial_time"`
    AvgDialTime     time.Duration          `json:"avg_dial_time"`
    LastError       string                 `json:"last_error"`
    LastSuccess     time.Time              `json:"last_success"`
    LastAttempt     time.Time              `json:"last_attempt"`
    ErrorsByType    map[string]int         `json:"errors_by_type"`
    mu              sync.RWMutex
}

// NewConnectionStats creates new connection statistics
func NewConnectionStats() *ConnectionStats {
    return &ConnectionStats{
        ErrorsByType: make(map[string]int),
    }
}

// RecordAttempt records a dial attempt
func (s *ConnectionStats) RecordAttempt() {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.DialAttempts++
    s.LastAttempt = time.Now()
}

// RecordSuccess records a successful dial
func (s *ConnectionStats) RecordSuccess(dialTime time.Duration) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    s.SuccessfulDials++
    s.TotalDialTime += dialTime
    s.LastSuccess = time.Now()
    s.LastAttempt = time.Now()
    
    if s.SuccessfulDials > 0 {
        s.AvgDialTime = s.TotalDialTime / time.Duration(s.SuccessfulDials)
    }
}

// RecordFailure records a failed dial
func (s *ConnectionStats) RecordFailure(err error, dialTime time.Duration) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    s.FailedDials++
    s.LastError = err.Error()
    s.LastAttempt = time.Now()
    s.TotalDialTime += dialTime
    
    // Categorize error
    errorType := "unknown"
    errStr := err.Error()
    
    if errors.Is(err, context.DeadlineExceeded) ||
        strings.Contains(errStr, "timeout") ||
        strings.Contains(errStr, "timed out") {
        errorType = "timeout"
    } else if strings.Contains(errStr, "no such host") ||
        strings.Contains(errStr, "Temporary failure in name resolution") ||
        strings.Contains(errStr, "server misbehaving") ||
        strings.Contains(errStr, "host lookup error") {
        errorType = "dns"
    } else if strings.Contains(errStr, "connection refused") ||
        strings.Contains(errStr, "network is unreachable") ||
        strings.Contains(errStr, "no route to host") ||
        strings.Contains(errStr, "reset by peer") ||
        strings.Contains(errStr, "connection reset") {
        errorType = "network"
    }
    
    s.ErrorsByType[errorType]++
}

// JSON returns JSON representation of stats
func (s *ConnectionStats) JSON() string {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    data := map[string]interface{}{
        "dial_attempts":    s.DialAttempts,
        "successful_dials": s.SuccessfulDials,
        "failed_dials":     s.FailedDials,
        "total_dial_time":  s.TotalDialTime.String(),
        "avg_dial_time":    s.AvgDialTime.String(),
        "last_error":       s.LastError,
        "last_success":     s.LastSuccess.Format(time.RFC3339),
        "last_attempt":     s.LastAttempt.Format(time.RFC3339),
        "errors_by_type":   s.ErrorsByType,
        "success_rate":     0.0,
    }
    
    if s.DialAttempts > 0 {
        data["success_rate"] = float64(s.SuccessfulDials) / float64(s.DialAttempts) * 100
    }
    
    jsonData, _ := json.Marshal(data)
    return string(jsonData)
}

// ==============================
// Tunnel Implementation
// ==============================

// Tunnel manages a single HTTP CONNECT tunnel connection
type Tunnel struct {
    connectionInfoPrefix string
    conn                 net.Conn
    lConn                net.Conn
    rConn                net.Conn
    lAddr                *net.TCPAddr
    remoteAddrStr        string
    sHost                Host
    earlyPinger          bool
    lPayload             []byte
    rPayload             []byte
    buffSize             uint64
    lInitialized         bool
    rInitialized         bool
    bytesReceived        uint64
    bytesSent            uint64
    erred                bool
    errSig               chan bool
    connId               uint64
    wsUpgradeInitialized bool
    mu                   sync.Mutex
    once                 sync.Once
    ctx                  context.Context
    cancel               context.CancelFunc
    
    // Enhanced fields
    dialStats            *ConnectionStats
    preferredIPFamily    string
    maxRetries           int
    dialTimeout          time.Duration
    dnsCache             *DNSCache
    enableFastFallback   bool
    healthCheckInterval  time.Duration
    lastHealthCheck      time.Time
    metrics              struct {
        startTime      time.Time
        activeDuration time.Duration
        peakBandwidth  uint64
    }
}

// Host represents a destination host
type Host struct {
    HostName string   `json:"hostname"`
    Port     uint64   `json:"port"`
    Resolved []net.IP `json:"resolved_ips,omitempty"`
}

// NewTunnel creates a new tunnel instance with enhanced configuration
func NewTunnel(connId uint64, conn net.Conn, lAddr *net.TCPAddr, remoteAddrStr string) *Tunnel {
    ctx, cancel := context.WithCancel(context.Background())
    
    t := &Tunnel{
        conn:                 conn,
        lConn:                conn,
        lAddr:                lAddr,
        remoteAddrStr:        remoteAddrStr,
        lPayload:             make([]byte, 0),
        rPayload:             make([]byte, 0),
        buffSize:             uint64(0xffff),
        lInitialized:         false,
        rInitialized:         false,
        erred:                false,
        errSig:               make(chan bool, 2),
        connId:               connId,
        wsUpgradeInitialized: false,
        earlyPinger:          false,
        ctx:                  ctx,
        cancel:               cancel,
        dialStats:            NewConnectionStats(),
        preferredIPFamily:    "ipv4",
        maxRetries:           3,
        dialTimeout:          10 * time.Second,
        dnsCache:             globalDNSCache,
        enableFastFallback:   true,
        healthCheckInterval:  30 * time.Second,
        lastHealthCheck:      time.Now(),
    }
    
    t.metrics.startTime = time.Now()
    t.connectionInfoPrefix = fmt.Sprintf("[SSH-HTTP] Connection #%d", connId)
    
    return t
}

// SetLocalPayload sets the local payload template
func (t *Tunnel) SetLocalPayload(lPayload string) {
    t.mu.Lock()
    defer t.mu.Unlock()
    t.lPayload = []byte(lPayload)
}

// SetRemotePayload sets the remote payload template
func (t *Tunnel) SetRemotePayload(rPayload string) {
    t.mu.Lock()
    defer t.mu.Unlock()
    
    if rPayload == "" {
        rPayload = "HTTP/1.1 200 Connection Established[crlf][crlf]"
    }
    rPayload = strings.Replace(rPayload, "[crlf]", "\r\n", -1)
    t.rPayload = []byte(rPayload)
}

// SetBufferSize sets the buffer size for data transfer
func (t *Tunnel) SetBufferSize(buffSize uint64) {
    t.mu.Lock()
    defer t.mu.Unlock()
    
    if buffSize < 1024 {
        buffSize = 1024
    }
    if buffSize > 65535 {
        buffSize = 65535
    }
    t.buffSize = buffSize
}

// SetEarlyPinger enables/disables early ping feature
func (t *Tunnel) SetEarlyPinger(enabled bool) {
    t.mu.Lock()
    defer t.mu.Unlock()
    t.earlyPinger = enabled
}

// SetDialConfig configures dial parameters
func (t *Tunnel) SetDialConfig(preferredIPFamily string, maxRetries int, dialTimeout time.Duration) {
    t.mu.Lock()
    defer t.mu.Unlock()
    
    if preferredIPFamily != "" {
        t.preferredIPFamily = preferredIPFamily
    }
    if maxRetries > 0 {
        t.maxRetries = maxRetries
    }
    if dialTimeout > 0 {
        t.dialTimeout = dialTimeout
    }
}

// SetFastFallback enables/disables fast fallback
func (t *Tunnel) SetFastFallback(enabled bool) {
    t.mu.Lock()
    defer t.mu.Unlock()
    t.enableFastFallback = enabled
}

// categorizeError categorizes network errors
func categorizeError(err error) (isTimeout, isDNSError, isNetwork bool) {
    if err == nil {
        return false, false, false
    }
    
    errStr := err.Error()
    
    // Timeout errors
    if errors.Is(err, context.DeadlineExceeded) ||
        strings.Contains(errStr, "timeout") ||
        strings.Contains(errStr, "timed out") {
        isTimeout = true
    }
    
    // DNS errors
    if strings.Contains(errStr, "no such host") ||
        strings.Contains(errStr, "Temporary failure in name resolution") ||
        strings.Contains(errStr, "server misbehaving") ||
        strings.Contains(errStr, "host lookup error") {
        isDNSError = true
    }
    
    // Network errors
    if strings.Contains(errStr, "connection refused") ||
        strings.Contains(errStr, "network is unreachable") ||
        strings.Contains(errStr, "no route to host") ||
        strings.Contains(errStr, "reset by peer") ||
        strings.Contains(errStr, "connection reset") {
        isNetwork = true
    }
    
    return isTimeout, isDNSError, isNetwork
}

// ==============================
// Enhanced DNS Resolution
// ==============================

// resolveHost performs DNS resolution with multiple strategies
func (t *Tunnel) resolveHost(ctx context.Context, host string) ([]net.IP, error) {
    startTime := time.Now()
    log.Debugln("%s Starting DNS resolution for %s", t.connectionInfoPrefix, host)
    
    // Strategy 1: Check cache first
    if cachedIPs, ok := t.dnsCache.Get(host); ok {
        log.Debugln("%s Using cached DNS for %s: %v", t.connectionInfoPrefix, host, cachedIPs)
        return cachedIPs, nil
    }
    
    var allErrors []string
    var resolvedIPs []net.IP
    
    // Strategy 2: System resolver with timeout
    if ips, err := t.resolveWithSystem(ctx, host); err == nil {
        resolvedIPs = ips
    } else {
        allErrors = append(allErrors, fmt.Sprintf("system: %v", err))
    }
    
    // Strategy 3: Custom resolver (Google DNS) if system fails
    if len(resolvedIPs) == 0 {
        log.Debugln("%s System DNS failed, trying custom resolver", t.connectionInfoPrefix)
        
        if ips, err := t.resolveWithCustom(ctx, host); err == nil {
            resolvedIPs = ips
        } else {
            allErrors = append(allErrors, fmt.Sprintf("custom: %v", err))
        }
    }
    
    // Strategy 4: Fallback to net.LookupHost
    if len(resolvedIPs) == 0 {
        log.Debugln("%s Custom DNS failed, trying net.LookupHost", t.connectionInfoPrefix)
        
        if ips, err := net.LookupHost(host); err == nil {
            for _, ipStr := range ips {
                if ip := net.ParseIP(ipStr); ip != nil {
                    resolvedIPs = append(resolvedIPs, ip)
                }
            }
        } else {
            allErrors = append(allErrors, fmt.Sprintf("lookuphost: %v", err))
        }
    }
    
    // Check results
    if len(resolvedIPs) == 0 {
        err := fmt.Errorf("all DNS resolution strategies failed: %v", strings.Join(allErrors, "; "))
        t.dnsCache.SetWithError(host, err)
        return nil, err
    }
    
    // Cache successful resolution
    t.dnsCache.Set(host, resolvedIPs)
    
    log.Debugln("%s DNS resolution successful for %s: %v (took %v)",
        t.connectionInfoPrefix, host, resolvedIPs, time.Since(startTime))
    
    return resolvedIPs, nil
}

// resolveWithSystem uses system resolver
func (t *Tunnel) resolveWithSystem(ctx context.Context, host string) ([]net.IP, error) {
    resolver := &net.Resolver{
        PreferGo: false, // Use system resolver
    }
    
    ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    
    addrs, err := resolver.LookupIPAddr(ctx, host)
    if err != nil {
        return nil, err
    }
    
    ips := make([]net.IP, len(addrs))
    for i, addr := range addrs {
        ips[i] = addr.IP
    }
    
    return ips, nil
}

// resolveWithCustom uses custom DNS servers
func (t *Tunnel) resolveWithCustom(ctx context.Context, host string) ([]net.IP, error) {
    // List of DNS servers to try
    dnsServers := []string{
        "8.8.8.8:53",        // Google
        "1.1.1.1:53",        // Cloudflare
        "208.67.222.222:53", // OpenDNS
    }
    
    var lastError error
    
    for _, server := range dnsServers {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        default:
        }
        
        resolver := &net.Resolver{
            PreferGo: true,
            Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
                d := net.Dialer{Timeout: 2 * time.Second}
                return d.DialContext(ctx, "udp", server)
            },
        }
        
        ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
        addrs, err := resolver.LookupIPAddr(ctx, host)
        cancel()
        
        if err == nil && len(addrs) > 0 {
            ips := make([]net.IP, len(addrs))
            for i, addr := range addrs {
                ips[i] = addr.IP
            }
            return ips, nil
        }
        
        lastError = err
        log.Debugln("%s DNS server %s failed: %v", t.connectionInfoPrefix, server, err)
    }
    
    return nil, fmt.Errorf("all custom DNS servers failed, last error: %w", lastError)
}

// sortIPsByPreference sorts IPs based on preference
func (t *Tunnel) sortIPsByPreference(ips []net.IP) []net.IP {
    if len(ips) <= 1 {
        return ips
    }
    
    var ipv4, ipv6 []net.IP
    for _, ip := range ips {
        if ip.To4() != nil {
            ipv4 = append(ipv4, ip)
        } else {
            ipv6 = append(ipv6, ip)
        }
    }
    
    // Shuffle each list for load balancing
    shuffle := func(slice []net.IP) {
        rand.New(rand.NewSource(time.Now().UnixNano())).Shuffle(len(slice), func(i, j int) {
            slice[i], slice[j] = slice[j], slice[i]
        })
    }
    
    shuffle(ipv4)
    shuffle(ipv6)
    
    // Return based on preference
    switch t.preferredIPFamily {
    case "ipv6":
        return append(ipv6, ipv4...)
    case "any":
        // Interleave IPv4 and IPv6
        var result []net.IP
        maxLen := len(ipv4)
        if len(ipv6) > maxLen {
            maxLen = len(ipv6)
        }
        for i := 0; i < maxLen; i++ {
            if i < len(ipv6) {
                result = append(result, ipv6[i])
            }
            if i < len(ipv4) {
                result = append(result, ipv4[i])
            }
        }
        return result
    default: // "ipv4" or anything else
        return append(ipv4, ipv6...)
    }
}

// ==============================
// Enhanced SmartDial
// ==============================

// smartDial is the enhanced dial function with caching, retry, and fallback
func (t *Tunnel) smartDial(ctx context.Context) (net.Conn, error) {
    startTime := time.Now()
    t.dialStats.RecordAttempt()
    
    log.Debugln("%s Starting smart dial to %s", t.connectionInfoPrefix, t.remoteAddrStr)
    
    // Parse host and port
    host, port, err := net.SplitHostPort(t.remoteAddrStr)
    if err != nil {
        // If not in host:port format, add default port
        host = t.remoteAddrStr
        port = "80"
        t.remoteAddrStr = net.JoinHostPort(host, port)
    }
    
    // Check if it's already an IP address
    if ip := net.ParseIP(host); ip != nil {
        log.Debugln("%s Direct IP address detected: %s", t.connectionInfoPrefix, ip)
        return t.dialWithRetry(ctx, host, port)
    }
    
    // Resolve hostname
    ips, err := t.resolveHost(ctx, host)
    if err != nil {
        dialTime := time.Since(startTime)
        t.dialStats.RecordFailure(err, dialTime)
        
        // Try emergency fallback
        log.Warnln("%s DNS resolution failed, trying emergency fallback: %v",
            t.connectionInfoPrefix, err)
        
        if conn, fallbackErr := t.emergencyFallback(ctx, host, port); fallbackErr == nil {
            t.dialStats.RecordSuccess(time.Since(startTime))
            return conn, nil
        }
        
        return nil, &DialError{
            Stage:      "dns_resolution",
            Host:       host,
            Address:    t.remoteAddrStr,
            Underlying: err,
            IsDNSError: true,
            Attempt:    1,
            TotalTime:  dialTime,
            Timestamp:  time.Now(),
        }
    }
    
    // Sort IPs by preference
    sortedIPs := t.sortIPsByPreference(ips)
    log.Debugln("%s Resolved %s to %d IPs, sorted: %v",
        t.connectionInfoPrefix, host, len(sortedIPs), sortedIPs)
    
    // Try each IP with retry
    var lastError error
    var errors []string
    
    for ipIndex, ip := range sortedIPs {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        default:
        }
        
        address := net.JoinHostPort(ip.String(), port)
        ipType := "IPv4"
        if ip.To4() == nil {
            ipType = "IPv6"
        }
        
        log.Debugln("%s Attempting connection to %s (%s)",
            t.connectionInfoPrefix, address, ipType)
        
        conn, err := t.dialWithRetry(ctx, ip.String(), port)
        if err == nil {
            dialTime := time.Since(startTime)
            t.dialStats.RecordSuccess(dialTime)
            
            log.Infoln("%s Successfully connected to %s via %s (took %v, tried %d IPs)",
                t.connectionInfoPrefix, host, ipType, dialTime, ipIndex+1)
            
            return conn, nil
        }
        
        // Categorize error
        isTimeout, isDNSError, isNetwork := categorizeError(err)
        errorType := "unknown"
        if isTimeout {
            errorType = "timeout"
        } else if isDNSError {
            errorType = "dns"
        } else if isNetwork {
            errorType = "network"
        }
        
        errors = append(errors, fmt.Sprintf("%s(%s): %v", address, errorType, err))
        lastError = err
        
        // Log the failure
        log.Debugln("%s Connection to %s failed: %v", t.connectionInfoPrefix, address, err)
        
        // Fast fail for certain error types
        if t.enableFastFallback && isNetwork && !strings.Contains(err.Error(), "timeout") {
            // Network errors (not timeout) are likely permanent for this IP
            continue
        }
    }
    
    // All IPs failed
    dialTime := time.Since(startTime)
    t.dialStats.RecordFailure(lastError, dialTime)
    
    // Try emergency fallback
    log.Warnln("%s All IPs failed for %s, trying emergency fallback",
        t.connectionInfoPrefix, host)
    
    if conn, fallbackErr := t.emergencyFallback(ctx, host, port); fallbackErr == nil {
        t.dialStats.RecordSuccess(time.Since(startTime))
        return conn, nil
    }
    
    return nil, &DialError{
        Stage:      "all_ips_failed",
        Host:       host,
        Address:    t.remoteAddrStr,
        Underlying: fmt.Errorf("all connection attempts failed: %v", strings.Join(errors, "; ")),
        IsTimeout:  strings.Contains(lastError.Error(), "timeout"),
        IsNetwork:  true,
        Attempt:    len(sortedIPs),
        TotalTime:  dialTime,
        Timestamp:  time.Now(),
    }
}

// dialWithRetry attempts to dial with retry mechanism
func (t *Tunnel) dialWithRetry(ctx context.Context, host, port string) (net.Conn, error) {
    address := net.JoinHostPort(host, port)
    var lastError error
    
    for attempt := 1; attempt <= t.maxRetries; attempt++ {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        default:
        }
        
        log.Debugln("%s Dial attempt %d/%d to %s",
            t.connectionInfoPrefix, attempt, t.maxRetries, address)
        
        // Create dialer with configured timeout
        dialer := &net.Dialer{
            Timeout:   t.dialTimeout,
            KeepAlive: 30 * time.Second,
            DualStack: true,
        }
        
        // Create context with timeout for this attempt
        attemptCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
        
        conn, err := dialer.DialContext(attemptCtx, "tcp", address)
        cancel()
        
        if err == nil {
            return conn, nil
        }
        
        lastError = err
        
        // Log attempt failure
        log.Debugln("%s Dial attempt %d failed: %v", t.connectionInfoPrefix, attempt, err)
        
        // Don't retry on certain errors
        if strings.Contains(err.Error(), "connection refused") ||
            strings.Contains(err.Error(), "no route to host") ||
            strings.Contains(err.Error(), "network is unreachable") {
            return nil, err
        }
        
        // Exponential backoff before next retry
        if attempt < t.maxRetries {
            backoff := time.Duration(attempt*attempt) * 500 * time.Millisecond
            log.Debugln("%s Waiting %v before next retry", t.connectionInfoPrefix, backoff)
            
            select {
            case <-time.After(backoff):
                continue
            case <-ctx.Done():
                return nil, ctx.Err()
            }
        }
    }
    
    return nil, fmt.Errorf("dial failed after %d attempts: %w", t.maxRetries, lastError)
}

// emergencyFallback tries last-resort connection methods
func (t *Tunnel) emergencyFallback(ctx context.Context, host, port string) (net.Conn, error) {
    log.Debugln("%s Starting emergency fallback for %s:%s", t.connectionInfoPrefix, host, port)
    
    // Method 1: Try with shorter timeout
    dialer := &net.Dialer{
        Timeout:   3 * time.Second,
        KeepAlive: 15 * time.Second,
    }
    
    address := net.JoinHostPort(host, port)
    if conn, err := dialer.DialContext(ctx, "tcp", address); err == nil {
        log.Debugln("%s Emergency fallback (direct) succeeded", t.connectionInfoPrefix)
        return conn, nil
    }
    
    // Method 2: Try alternative ports
    altPorts := []string{"8080", "443", "8443", "3128"}
    for _, altPort := range altPorts {
        if altPort == port {
            continue
        }
        
        altAddress := net.JoinHostPort(host, altPort)
        if conn, err := dialer.DialContext(ctx, "tcp", altAddress); err == nil {
            log.Debugln("%s Emergency fallback (port %s) succeeded", t.connectionInfoPrefix, altPort)
            return conn, nil
        }
    }
    
    return nil, errors.New("all emergency fallback methods failed")
}

// ==============================
// Enhanced Tunnel Methods
// ==============================

// Start starts the tunnel data transfer with enhanced error handling
func (t *Tunnel) Start() {
    defer func() {
        if r := recover(); r != nil {
            log.Errorln("%s PANIC recovered in tunnel: %v", t.connectionInfoPrefix, r)
        }
        t.cancel()
    }()
    
    defer t.closeConnection(t.lConn)
    
    log.Infoln("%s Starting tunnel to %s", t.connectionInfoPrefix, t.remoteAddrStr)
    
    // Create context with overall timeout
    dialCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // Dial remote connection
    startTime := time.Now()
    var err error
    t.rConn, err = t.smartDial(dialCtx)
    
    if err != nil {
        // Detailed error logging
        var dialErr *DialError
        if errors.As(err, &dialErr) {
            log.Errorln("%s Dial failed: %s", t.connectionInfoPrefix, dialErr.JSON())
        } else {
            log.Errorln("%s Dial failed: %v (took %v)",
                t.connectionInfoPrefix, err, time.Since(startTime))
        }
        
        // Log statistics
        log.Debugln("%s Connection stats: %s", t.connectionInfoPrefix, t.dialStats.JSON())
        return
    }
    
    defer func() {
        if t.rConn != nil {
            t.closeConnection(t.rConn)
        }
    }()
    
    // Update metrics
    t.metrics.activeDuration = time.Since(startTime)
    
    log.Infoln("%s Tunnel established %s >> %s (via %s, took %v)",
        t.connectionInfoPrefix, t.lConn.RemoteAddr(), t.remoteAddrStr,
        t.rConn.RemoteAddr(), time.Since(startTime))
    
    // Start bidirectional data forwarding
    wg := sync.WaitGroup{}
    wg.Add(2)
    
    go func() {
        defer wg.Done()
        t.handleForwardData(t.lConn, t.rConn)
    }()
    
    go func() {
        defer wg.Done()
        t.handleForwardData(t.rConn, t.lConn)
    }()
    
    // Start health check goroutine
    healthCheckDone := make(chan bool, 1)
    go t.healthCheckLoop(healthCheckDone)
    
    // Wait for completion
    select {
    case <-t.errSig:
        log.Debugln("%s Tunnel closed by error signal", t.connectionInfoPrefix)
    case <-t.ctx.Done():
        log.Debugln("%s Tunnel closed by context", t.connectionInfoPrefix)
    case <-time.After(24 * time.Hour): // 24-hour maximum
        log.Warnln("%s Tunnel timeout after 24 hours", t.connectionInfoPrefix)
        t.err()
    }
    
    // Stop health checks
    close(healthCheckDone)
    
    // Wait for forwarders to finish
    wg.Wait()
    
    // Final log
    t.metrics.activeDuration = time.Since(startTime)
    log.Infoln("%s Tunnel closed (%d bytes sent, %d bytes received, duration: %v)",
        t.connectionInfoPrefix, t.bytesSent, t.bytesReceived, t.metrics.activeDuration)
}

// healthCheckLoop performs periodic health checks
func (t *Tunnel) healthCheckLoop(done <-chan bool) {
    ticker := time.NewTicker(t.healthCheckInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-done:
            return
        case <-ticker.C:
            if !t.healthCheck() {
                log.Warnln("%s Health check failed, closing tunnel", t.connectionInfoPrefix)
                t.err()
                return
            }
            t.lastHealthCheck = time.Now()
        }
    }
}

// healthCheck performs a health check on the tunnel
func (t *Tunnel) healthCheck() bool {
    t.mu.Lock()
    defer t.mu.Unlock()
    
    if t.erred || t.ctx.Err() != nil {
        return false
    }
    
    // Check if connections are still writable
    checkConn := func(conn net.Conn) bool {
        if conn == nil {
            return false
        }
        
        // Try to write a small amount of data
        conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
        _, err := conn.Write([]byte{0})
        conn.SetWriteDeadline(time.Time{})
        
        if err != nil {
            log.Debugln("%s Health check write failed: %v", t.connectionInfoPrefix, err)
            return false
        }
        
        return true
    }
    
    return checkConn(t.lConn) && checkConn(t.rConn)
}

// Cancel cancels the tunnel context
func (t *Tunnel) Cancel() {
    t.cancel()
}

// closeConnection safely closes a connection
func (t *Tunnel) closeConnection(conn net.Conn) {
    if conn != nil {
        if err := conn.Close(); err != nil {
            log.Debugln("%s Error closing connection: %s", t.connectionInfoPrefix, err)
        }
    }
}

// err signals an error and initiates cleanup
func (t *Tunnel) err() {
    t.once.Do(func() {
        t.mu.Lock()
        t.erred = true
        t.mu.Unlock()
        
        select {
        case t.errSig <- true:
        default:
        }
        
        t.cancel()
    })
}

// ==============================
// Data Forwarding Methods
// ==============================

// handleForwardData handles data forwarding between two connections
func (t *Tunnel) handleForwardData(src, dst net.Conn) {
    isLocal := src == t.lConn
    buffer := make([]byte, t.buffSize)
    
    defer func() {
        if r := recover(); r != nil {
            log.Errorln("%s PANIC in handleForwardData: %v", t.connectionInfoPrefix, r)
        }
        t.err()
    }()
    
    for {
        select {
        case <-t.ctx.Done():
            return
        default:
            // Read with timeout
            src.SetReadDeadline(time.Now().Add(30 * time.Second))
            n, err := src.Read(buffer)
            src.SetReadDeadline(time.Time{})
            
            if err != nil {
                if errors.Is(err, net.ErrClosed) ||
                    strings.Contains(err.Error(), "use of closed network connection") {
                    log.Debugln("%s Connection closed normally: %s", t.connectionInfoPrefix, err)
                } else if err.Error() == "EOF" {
                    log.Debugln("%s EOF reached", t.connectionInfoPrefix)
                } else {
                    log.Errorln("%s Read error: %s", t.connectionInfoPrefix, err)
                }
                t.err()
                return
            }
            
            if n == 0 {
                t.err()
                return
            }
            
            connBuff := buffer[:n]
            
            // Process data based on direction
            if isLocal {
                t.handleOutboundData(src, dst, &connBuff)
            } else {
                t.handleInboundData(src, dst, &connBuff)
            }
            
            // Write data
            dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
            _, err = dst.Write(connBuff)
            dst.SetWriteDeadline(time.Time{})
            
            if err != nil {
                if errors.Is(err, net.ErrClosed) ||
                    strings.Contains(err.Error(), "use of closed network connection") {
                    log.Debugln("%s Connection closed during write: %s", t.connectionInfoPrefix, err)
                } else {
                    log.Errorln("%s Write error: %s", t.connectionInfoPrefix, err)
                }
                t.err()
                return
            }
            
            // Update statistics
            if isLocal {
                t.bytesSent += uint64(n)
                // Track peak bandwidth
                if uint64(n) > t.metrics.peakBandwidth {
                    t.metrics.peakBandwidth = uint64(n)
                }
            } else {
                t.bytesReceived += uint64(n)
            }
        }
    }
}

// handleOutboundData processes outbound (client -> server) data
func (t *Tunnel) handleOutboundData(src, dst net.Conn, connBuff *[]byte) {
    if t.lInitialized {
        return
    }
    
    log.Infoln("%s %s >> %s >> %s", t.connectionInfoPrefix,
        src.RemoteAddr(), t.conn.LocalAddr(), dst.RemoteAddr())
    
    // Parse HTTP CONNECT request
    var respArr []string
    buffScanner := bufio.NewScanner(strings.NewReader(string(*connBuff)))
    for buffScanner.Scan() {
        respArr = append(respArr, buffScanner.Text())
    }
    
    if len(respArr) > 0 && strings.Contains(respArr[0], "CONNECT ") {
        parts := strings.Split(respArr[0], " ")
        if len(parts) >= 2 {
            hostPort := parts[1]
            sHost, sPort, err := net.SplitHostPort(hostPort)
            if err != nil {
                sHost = hostPort
                sPort = "80"
            }
            sPortParsed, err := strconv.ParseUint(sPort, 10, 64)
            if err != nil {
                sPortParsed = 80
            }
            
            t.sHost = Host{
                HostName: sHost,
                Port:     sPortParsed,
            }
            
            // Process local payload template
            if len(t.lPayload) > 0 {
                lPayloadStr := string(t.lPayload)
                lPayloadStr = strings.Replace(lPayloadStr, "[host]", t.sHost.HostName, -1)
                lPayloadStr = strings.Replace(lPayloadStr, "[host_port]",
                    fmt.Sprintf("%s:%d", t.sHost.HostName, t.sHost.Port), -1)
                lPayloadStr = strings.Replace(lPayloadStr, "[crlf]", "\r\n", -1)
                lPayloadStr = strings.Replace(lPayloadStr, "[crlf*2]", "\r\n\r\n", -1)
                lPayloadStr = strings.Replace(lPayloadStr, "[lf]", "\n", -1)
                lPayloadStr = strings.Replace(lPayloadStr, "[cr]", "\r", -1)
                lPayloadStr = strings.Replace(lPayloadStr, "[protocol]", "HTTP/1.1", -1)
                lPayloadStr = strings.Replace(lPayloadStr, "[ua]", "Dalvik/2.1.0", -1)
                t.lPayload = []byte(lPayloadStr)
            }
        }
        
        // Early ping if enabled
        if t.earlyPinger && t.sHost.HostName != "" && t.sHost.HostName != "localhost" {
            go t.doPing(t.sHost.HostName)
        }
        
        // Apply local payload
        if len(t.lPayload) > 0 {
            *connBuff = t.lPayload
            log.Debugln("%s Outbound payload: %s", t.connectionInfoPrefix, string(*connBuff))
        }
    }
    
    t.lInitialized = true
}

// handleInboundData processes inbound (server -> client) data
func (t *Tunnel) handleInboundData(src, dst net.Conn, connBuff *[]byte) {
    if t.rInitialized {
        return
    }
    
    log.Infoln("%s %s << %s << %s", t.connectionInfoPrefix,
        dst.RemoteAddr(), t.conn.LocalAddr(), src.RemoteAddr())
    
    var respArr []string
    buffScanner := bufio.NewScanner(strings.NewReader(string(*connBuff)))
    for buffScanner.Scan() {
        respArr = append(respArr, buffScanner.Text())
    }
    
    // Handle WebSocket upgrade responses
    if len(respArr) > 0 && strings.Contains(respArr[0], " 101 ") {
        respArr[0] = strings.Replace(string(t.rPayload), "\r\n", "", -1)
    }
    
    // Apply remote payload
    if len(respArr) > 0 {
        *connBuff = []byte(strings.Join(respArr, "\r\n") + "\r\n")
        log.Debugln("%s Inbound payload: %s", t.connectionInfoPrefix, string(*connBuff))
    }
    
    t.rInitialized = true
}

// ==============================
// Utility Methods
// ==============================

// doPing performs an early ping to warm up connections
func (t *Tunnel) doPing(host string) {
    defer func() {
        if r := recover(); r != nil {
            log.Debugln("%s Ping recovered from panic: %v", t.connectionInfoPrefix, r)
        }
    }()
    
    client := &http.Client{
        Timeout: 3 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
        },
    }
    
    go func() {
        urls := []string{
            fmt.Sprintf("http://%s", host),
            fmt.Sprintf("https://%s", host),
        }
        
        for _, url := range urls {
            resp, err := client.Get(url)
            if err != nil {
                log.Debugln("%s Ping %s failed: %v", t.connectionInfoPrefix, url, err)
                continue
            }
            resp.Body.Close()
            log.Debugln("%s Ping %s successful: %s", t.connectionInfoPrefix, url, resp.Status)
            break
        }
    }()
}

// GetMetrics returns tunnel metrics
func (t *Tunnel) GetMetrics() map[string]interface{} {
    t.mu.Lock()
    defer t.mu.Unlock()
    
    localAddr := ""
    remoteAddr := ""
    if t.lConn != nil {
        localAddr = t.lConn.RemoteAddr().String()
    }
    if t.rConn != nil {
        remoteAddr = t.rConn.RemoteAddr().String()
    }
    
    return map[string]interface{}{
        "connection_id":          t.connId,
        "start_time":             t.metrics.startTime.Format(time.RFC3339),
        "active_duration":        t.metrics.activeDuration.String(),
        "local_initialized":      t.lInitialized,
        "remote_initialized":     t.rInitialized,
        "bytes_sent":             t.bytesSent,
        "bytes_received":         t.bytesReceived,
        "local_addr":             localAddr,
        "remote_addr":            remoteAddr,
        "target_host":            t.remoteAddrStr,
        "buffer_size":            t.buffSize,
        "erred":                  t.erred,
        "ws_upgrade":             t.wsUpgradeInitialized,
        "early_pinger":           t.earlyPinger,
        "peak_bandwidth":         t.metrics.peakBandwidth,
        "dial_stats":             t.dialStats,
        "preferred_ip_family":    t.preferredIPFamily,
        "max_retries":            t.maxRetries,
        "dial_timeout":           t.dialTimeout.String(),
        "enable_fast_fallback":   t.enableFastFallback,
        "health_check_interval":  t.healthCheckInterval.String(),
        "last_health_check":      t.lastHealthCheck.Format(time.RFC3339),
        "context_error":          t.ctx.Err(),
    }
}

// GetDebugInfo returns detailed debug information
func (t *Tunnel) GetDebugInfo() string {
    metrics := t.GetMetrics()
    
    // Add DNS cache stats
    metrics["dns_cache_stats"] = t.dnsCache.Stats()
    
    jsonData, err := json.MarshalIndent(metrics, "", "  ")
    if err != nil {
        return fmt.Sprintf("Error marshaling debug info: %v", err)
    }
    
    return string(jsonData)
}

// IsHealthy checks if the tunnel is healthy
func (t *Tunnel) IsHealthy() bool {
    t.mu.Lock()
    defer t.mu.Unlock()
    
    if t.erred || t.ctx.Err() != nil {
        return false
    }
    
    // Check if connections exist
    if t.lConn == nil || t.rConn == nil {
        return false
    }
    
    // Check last health check time
    if time.Since(t.lastHealthCheck) > t.healthCheckInterval*2 {
        return false
    }
    
    return true
}

// Reset resets the tunnel for reuse
func (t *Tunnel) Reset() {
    t.mu.Lock()
    defer t.mu.Unlock()
    
    t.lInitialized = false
    t.rInitialized = false
    t.bytesReceived = 0
    t.bytesSent = 0
    t.erred = false
    t.wsUpgradeInitialized = false
    
    // Reset error channel
    select {
    case <-t.errSig:
    default:
    }
    
    // Create new context
    t.ctx, t.cancel = context.WithCancel(context.Background())
    t.metrics.startTime = time.Now()
    t.metrics.activeDuration = 0
    t.metrics.peakBandwidth = 0
}
